use std::{fs, path::{Path, PathBuf}};

use aws_sdk_s3::operation::create_multipart_upload::CreateMultipartUploadOutput;
//use aws_sdk_s3::primitives::ByteStream::from_path;
use crate::client::S3ExampleError;
use anyhow::{Context, Result};
use aws_config::{
    meta::region::{self, RegionProviderChain},
    BehaviorVersion,
};
use aws_sdk_s3::{config::Region, operation::delete_objects, Client};
use tokio::io::AsyncWriteExt;
use uuid::Uuid;
pub struct S3Client {
    client: aws_sdk_s3::Client,
    bucket_name: String,
    path: String,
}

impl S3Client {
    pub async fn new(bucket_name: impl Into<String>, path: impl Into<String>) -> Result<Self> {
        let region_provider =
            RegionProviderChain::default_provider().or_else(Region::new("ca-central-1")); // fallback only
        let config = aws_config::defaults(BehaviorVersion::latest())
            .region(region_provider)
            .load()
            .await;

        let client = Client::new(&config);
        Ok(Self {
            client,
            bucket_name: bucket_name.into(),
            path: path.into(),
        })
    }

pub async fn replace_and_upload(&self) -> Result<()> {
    // self.key should be the S3 object key (the thing you pass to get_object)
    // self.path should be the LOCAL path to the file you want to upload

    upload_object(
        &self.client,
        &self.bucket_name,
        &self.path,   // local file path
        "enclave-mappings.json",    // s3 object key
    )
    .await?;

    Ok(())
}


    pub async fn remove_and_download(&self) -> Result<()> {
        Ok(())
    }

pub async fn download(&self) -> Result<()> {
    // 1) Get object
    let out = self.client
        .get_object()
        .bucket(&self.bucket_name)
        .key(&self.path)
        .send()
        .await
        .with_context(|| format!("get_object failed for s3://{}/{}", self.bucket_name, self.path))?;

    // 2) Build destination path: <project_root>/data/enclave-mappings.json
    let mut dest_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    dest_path.push("data");
    dest_path.push("enclave-mappings.json");

    // 3) Ensure parent dir exists
    if let Some(parent) = dest_path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("Failed to create dir {}", parent.display()))?;
    }

    // 4) Read bytes (small file) and write
    let bytes = out.body.collect().await?.into_bytes();
    tokio::fs::write(&dest_path, &bytes)
        .await
        .with_context(|| format!("Failed to write {}", dest_path.display()))?;

    println!("Wrote {} bytes to {}", bytes.len(), dest_path.display());
    Ok(())
}


    pub async fn check_mappings_file(&self) -> Result<String> {
        let path = Path::new("../../data/address_mappings.json");

        if ensure_address_mappings_exists() {
            if path.exists() {
                // fs::remove_file(path)
                //     .with_context(|| format!("Failed to delete {}", path.display()))?;
            }

            Ok("File in directory already exists".to_string())
        } else {
            println!("This path doesn't exist...");
            self.download().await?;
            Ok("File missing, downloading...".to_string())
        }
    }
}

pub async fn download_object(
    client: &aws_sdk_s3::Client,
    bucket_name: &str,
    key: &str,
) -> Result<aws_sdk_s3::operation::get_object::GetObjectOutput, S3ExampleError> {
    client
        .get_object()
        .bucket(bucket_name)
        .key(key)
        .send()
        .await
        .map_err(S3ExampleError::from)
}

pub async fn list_objects(client: &aws_sdk_s3::Client, bucket: &str) -> Result<(), S3ExampleError> {
    let mut response = client
        .list_objects_v2()
        .bucket(bucket.to_owned())
        .max_keys(10) // In this example, go 10 at a time.
        .into_paginator()
        .send();

    while let Some(result) = response.next().await {
        match result {
            Ok(output) => {
                for object in output.contents() {
                    println!(" - {}", object.key().unwrap_or("Unknown"));
                }
            }
            Err(err) => {
                eprintln!("{err:?}")
            }
        }
    }

    Ok(())
}

/// Given a bucket, remove all objects in the bucket, and then ensure no objects
/// remain in the bucket.
pub async fn clear_bucket(
    client: &aws_sdk_s3::Client,
    bucket_name: &str,
) -> Result<Vec<String>, S3ExampleError> {
    let objects = client.list_objects_v2().bucket(bucket_name).send().await?;

    // delete_objects no longer needs to be mutable.
    let objects_to_delete: Vec<String> = objects
        .contents()
        .iter()
        .filter_map(|obj| obj.key())
        .map(String::from)
        .collect();

    if objects_to_delete.is_empty() {
        return Ok(vec![]);
    }

    let return_keys = objects_to_delete.clone();

    delete_objects(client, bucket_name, objects_to_delete).await?;

    let objects = client.list_objects_v2().bucket(bucket_name).send().await?;

    eprintln!("{objects:?}");

    match objects.key_count {
        Some(0) => Ok(return_keys),
        _ => Err(S3ExampleError::new(
            "There were still objects left in the bucket.",
        )),
    }
}

pub async fn upload_object(
    client: &aws_sdk_s3::Client,
    bucket_name: &str,
    file_name: &str,
    key: &str,
) -> Result<aws_sdk_s3::operation::put_object::PutObjectOutput, S3ExampleError> {
    let body = aws_sdk_s3::primitives::ByteStream::from_path(std::path::Path::new(file_name)).await;
    client
        .put_object()
        .bucket(bucket_name)
        .key(key)
        .body(body.unwrap())
        .send()
        .await
        .map_err(S3ExampleError::from)
}

/// Delete the objects in a bucket.
pub async fn delete_objects(
    client: &aws_sdk_s3::Client,
    bucket_name: &str,
    objects_to_delete: Vec<String>,
) -> Result<(), S3ExampleError> {
    // Push into a mut vector to use `?` early return errors while building object keys.
    let mut delete_object_ids: Vec<aws_sdk_s3::types::ObjectIdentifier> = vec![];
    for obj in objects_to_delete {
        let obj_id = aws_sdk_s3::types::ObjectIdentifier::builder()
            .key(obj)
            .build()
            .map_err(|err| {
                S3ExampleError::new(format!("Failed to build key for delete_object: {err:?}"))
            })?;
        delete_object_ids.push(obj_id);
    }

    client
        .delete_objects()
        .bucket(bucket_name)
        .delete(
            aws_sdk_s3::types::Delete::builder()
                .set_objects(Some(delete_object_ids))
                .build()
                .map_err(|err| {
                    S3ExampleError::new(format!("Failed to build delete_object input {err:?}"))
                })?,
        )
        .send()
        .await?;
    Ok(())
}

pub fn ensure_address_mappings_exists() -> bool {
    let path = Path::new("../../data/address_mappings.json");

    if path.exists() && path.is_file() {
        return true;
    } else {
        return false;
    }
}
