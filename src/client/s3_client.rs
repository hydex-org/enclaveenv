

use std::{fs, path::Path};

use aws_sdk_s3::operation::create_multipart_upload::CreateMultipartUploadOutput;
//use aws_sdk_s3::primitives::ByteStream::from_path;
use aws_config::meta::region::{self, RegionProviderChain};
use aws_sdk_s3::{Client, config::Region, operation::delete_objects};
use crate::client::S3ExampleError;
use anyhow::{Context, Result};
use tokio::io::AsyncWriteExt;
use uuid::Uuid;
pub struct S3Client{
    client: aws_sdk_s3::Client,
    bucket_name: String,
    key: String,
}

impl S3Client{

    pub async fn new(
        bucket_name: impl Into<String>, 
        key: impl Into<String>,
    ) -> Result<Self> {
        let region_provider = RegionProviderChain::first_try(Region::new("us-west-2"));
        let config = aws_config::from_env()
            .region(region_provider)
            .load()
            .await;

        let client = Client::new(&config);
        Ok(Self {
            client,
            bucket_name: bucket_name.into(),
            key: key.into(),
        })
    }

pub async fn replace_and_upload(
    &self,
) -> Result<()> {
    // clear bucket
    clear_bucket(&self.client, &self.bucket_name.to_string());
    // upload to bucket
    upload_object(&self.client, &self.bucket_name.to_string(), "../../data/address_mappings.json", &self.key.to_string());
    Ok(())
}

pub async fn download(
    &self,
) -> Result<()> {
        // Choose where you want it saved:
    let dest_path = Path::new("../../data/address_mappings.json");

    // 1) Download (this returns GetObjectOutput with a streaming body)
    let out = download_object(&self.client, &self.bucket_name, &self.key)
        .await
        .map_err(|e| anyhow::anyhow!(e))
        .context("Failed to download object from S3")?;

        // 2) Ensure parent folder exists
    if let Some(parent) = dest_path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("Failed to create dir {}", parent.display()))?;
    }

        // 3) Create/overwrite the destination file
    let mut file = tokio::fs::File::create(dest_path)
        .await
        .with_context(|| format!("Failed to create {}", dest_path.display()))?;

    // 4) Stream body -> file
    let mut reader = out.body.into_async_read(); // requires aws-smithy-types feature "rt-tokio"
    tokio::io::copy(&mut reader, &mut file)
        .await
        .with_context(|| format!("Failed to write to {}", dest_path.display()))?;

    file.flush().await?;
    Ok(())
}

pub async fn check_mappings_file(
    &self,
) -> Result<()> {
    if(ensure_address_mappings_exists()){
        let path = Path::new("../../data/address_mappings.json");

        if path.exists() {
            fs::remove_file(path)
                .with_context(|| format!("Failed to delete {}", path.display()))?;
        }


    }
    else{   
        // Download
        self.download();
    }
    Ok(())
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

