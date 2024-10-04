use actix_multipart::Multipart;
use actix_web::HttpResponse;
use aws_config::{BehaviorVersion, Region};
use aws_sdk_s3::{config::Credentials, primitives::ByteStream};
use dotenv::dotenv;
use serde_json::json;
use futures::TryStreamExt;
use aws_sdk_s3 as s3;

pub async fn upload_file(mut payload: Multipart) -> HttpResponse {
  
  dotenv().ok();

  let aws_access_key_id = std::env::var("AWS_ACCESS_KEY_ID").expect("AWS_ACCESS_KEY_ID must be set.");
  let aws_secret_access_key = std::env::var("AWS_SECRET_ACCESS_KEY").expect("AWS_SECRET_ACCESS_KEY must be set.");
  let aws_region = std::env::var("AWS_REGION").expect("AWS_REGION must be set.");
  let s3_bucket = std::env::var("S3_BUCKET").expect("AWS_BUCKET must be set.");


  let creds = Credentials::new(aws_access_key_id, aws_secret_access_key, None, None, "ag-provides");
  let my_config = aws_config::defaults(BehaviorVersion::latest())
      .test_credentials()
      .region(Region::new(aws_region))
      .credentials_provider(creds)
      .load()
      .await;

  let s3_client = s3::Client::new(&my_config);

  let mut file_name2 = String::new();
  while let Ok(Some(mut field)) = payload.try_next().await {

    let s3_b = s3_bucket.clone();

    let content_type = field.content_disposition().unwrap();
    let filename = content_type.get_filename().unwrap().to_string();
    let mut file_data: Vec<u8> = Vec::new();
      
    while let Ok(Some(chunk)) = field.try_next().await {
      file_data.extend_from_slice(&chunk);
    }

    let byte_stream = file_data;
    let body = ByteStream::from(byte_stream);

    let put_object =  s3_client.put_object()
    .bucket(s3_b)
    .key(&filename)
    .body(body)
    .send()
    .await;

    if put_object.is_ok() {
      file_name2 = filename;
    }
   
  }

  HttpResponse::Ok().json(json!({
    "status": "success",
    "data": "Uploaded",
    "filename": file_name2
   }))
}
