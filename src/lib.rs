use worker::*;
use serde::{Deserialize, Serialize};
use serde_json::json;
use rand::Rng;
use std::time::{SystemTime, UNIX_EPOCH};
use reqwest::Client;
use hex::encode;

#[derive(Serialize, Deserialize)]
struct User {
    user_id: i64,
    username: String,
    api_key: String,
    created_at: String,
    is_blocked: bool,
    is_verified: bool,
}

#[derive(Deserialize)]
struct RegisterUser {
    user_id: i64,
}

#[derive(Deserialize)]
struct LoginUser {
    user_id: i64,
}

#[derive(Deserialize)]
struct OTPRequest {
    user_id: i64,
    api_key: String,
}

#[derive(Deserialize)]
struct OTPVerify {
    user_id: i64,
    otp: String,
}

#[derive(Deserialize)]
struct BlockUser {
    user_id: i64,
    block: bool,
    api_key: String,
    custom_message: Option<String>,
}

#[derive(Deserialize)]
struct GetUser {
    user_id: i64,
    api_key: String,
}

#[derive(Deserialize)]
struct AdminRequest {
    api_key: String,
}

#[derive(Deserialize)]
struct BroadcastRequest {
    api_key: String,
    message: String,
}

#[derive(Deserialize)]
struct TelegramMessage {
    message: Option<TelegramMessageContent>,
}

#[derive(Deserialize)]
struct TelegramMessageContent {
    chat: TelegramChat,
    text: Option<String>,
    from: TelegramUser,
}

#[derive(Deserialize)]
struct TelegramChat {
    id: i64,
    #[serde(rename = "type")]
    chat_type: String,
}

#[derive(Deserialize)]
struct TelegramUser {
    id: i64,
    username: Option<String>,
}

async fn send_telegram_message(chat_id: i64, text: String, env: &Env) -> Result<()> {
    let client = Client::new();
    let bot_token = env.var("TELEGRAM_BOT_TOKEN")?.to_string();
    let url = format!("https://api.telegram.org/bot{}/sendMessage", bot_token);
    
    let payload = json!({
        "chat_id": chat_id,
        "text": text,
        "parse_mode": "Markdown"
    });

    let response = client.post(&url).json(&payload).send().await?;
    if !response.status().is_success() {
        return Err(Error::RustError(format!("Telegram API error: {}", response.text().await?)));
    }
    Ok(())
}

fn generate_otp() -> String {
    let mut rng = rand::thread_rng();
    let bytes: [u8; 3] = [rng.gen(), rng.gen(), rng.gen()];
    encode(bytes).to_uppercase()
}

fn generate_api_key() -> String {
    let bytes: [u8; 16] = rand::thread_rng().gen();
    encode(bytes)
}

async fn verify_api_key(user_id: i64, api_key: &str, env: &Env) -> Result<User> {
    let user_data = get_redis_data(user_id, env).await?;
    let user: User = serde_json::from_str(&user_data)
        .map_err(|e| Error::RustError(format!("Invalid user data: {}", e)))?;
    
    if user.api_key != api_key {
        return Err(Error::RustError("Invalid API Key".to_string()));
    }
    if user.is_blocked {
        return Err(Error::RustError("User is blocked".to_string()));
    }
    if !user.is_verified {
        return Err(Error::RustError("User is not verified".to_string()));
    }
    Ok(user)
}

async fn verify_admin_api_key(api_key: &str, env: &Env) -> Result<()> {
    let admin_api_key = env.var("ADMIN_API_KEY")?.to_string();
    if api_key != admin_api_key {
        return Err(Error::RustError("Invalid Admin API Key".to_string()));
    }
    Ok(())
}

async fn verify_telegram_user(user_id: i64, env: &Env) -> Result<String> {
    let client = Client::new();
    let bot_token = env.var("TELEGRAM_BOT_TOKEN")?.to_string();
    let url = format!("https://api.telegram.org/bot{}/getChat?chat_id={}", bot_token, user_id);
    
    let response = client.get(&url).send().await?;
    if !response.status().is_success() {
        return Err(Error::RustError(format!("Invalid Telegram user ID: {}", response.status())));
    }
    
    let data: serde_json::Value = response.json().await?;
    if !data["ok"].as_bool().unwrap_or(false) {
        return Err(Error::RustError(data["description"].as_str().unwrap_or("Unknown error").to_string()));
    }
    
    let chat = &data["result"];
    if chat["type"].as_str().unwrap_or("") != "private" {
        return Err(Error::RustError("Invalid chat type".to_string()));
    }
    
    let username = chat["username"].as_str().unwrap_or(&format!("User_{}", user_id)).to_string();
    Ok(username)
}

async fn get_redis_data(key: i64, env: &Env) -> Result<String> {
    let redis_url = env.var("REDIS_URL")?.to_string();
    let redis_token = env.var("REDIS_TOKEN")?.to_string();
    let client = Client::new();
    let url = format!("{}/get/user:{}", redis_url, key);
    
    let response = client.get(&url)
        .header("Authorization", format!("Bearer {}", redis_token))
        .send().await?;
    
    if !response.status().is_success() {
        return Err(Error::RustError("User not found".to_string()));
    }
    
    let data: serde_json::Value = response.json().await?;
    data["result"]
        .as_str()
        .ok_or_else(|| Error::RustError("Invalid Redis response".to_string()))
        .map(|s| s.to_string())
}

async fn set_redis_data(key: i64, value: &str, env: &Env) -> Result<()> {
    let redis_url = env.var("REDIS_URL")?.to_string();
    let redis_token = env.var("REDIS_TOKEN")?.to_string();
    let client = Client::new();
    let url = format!("{}/set/user:{}/{}", redis_url, key, value);
    
    let response = client.post(&url)
        .header("Authorization", format!("Bearer {}", redis_token))
        .send().await?;
    
    if !response.status().is_success() {
        return Err(Error::RustError("Failed to set Redis data".to_string()));
    }
    Ok(())
}

async fn store_otp_to_redis(user_id: i64, otp: &str, env: &Env) -> Result<()> {
    let key = format!("otp:{}", user_id);
    let redis_url = env.var("REDIS_URL")?.to_string();
    let redis_token = env.var("REDIS_TOKEN")?.to_string();
    let client = Client::new();
    let url = format!("{}/set/{}:{}", redis_url, key, otp);
    
    let response = client.post(&url)
        .header("Authorization", format!("Bearer {}", redis_token))
        .send().await?;
    
    if !response.status().is_success() {
        return Err(Error::RustError("Failed to store OTP".to_string()));
    }
    
    // Set expiration to 5 minutes (300 seconds)
    let url = format!("{}/expire/{}:{}", redis_url, key, 300);
    let response = client.post(&url)
        .header("Authorization", format!("Bearer {}", redis_token))
        .send().await?;
    
    if !response.status().is_success() {
        return Err(Error::RustError("Failed to set OTP expiration".to_string()));
    }
    Ok(())
}

async fn retrieve_otp_from_redis(user_id: i64, env: &Env) -> Result<Option<String>> {
    let key = format!("otp:{}", user_id);
    let redis_url = env.var("REDIS_URL")?.to_string();
    let redis_token = env.var("REDIS_TOKEN")?.to_string();
    let client = Client::new();
    let url = format!("{}/get/{}", redis_url, key);
    
    let response = client.get(&url)
        .header("Authorization", format!("Bearer {}", redis_token))
        .send().await?;
    
    if !response.status().is_success() {
        return Ok(None);
    }
    
    let data: serde_json::Value = response.json().await?;
    Ok(data["result"].as_str().map(|s| s.to_string()))
}

async fn add_user_to_set(user_id: i64, env: &Env) -> Result<()> {
    let redis_url = env.var("REDIS_URL")?.to_string();
    let redis_token = env.var("REDIS_TOKEN")?.to_string();
    let client = Client::new();
    let url = format!("{}/sadd/users/{}", redis_url, user_id);
    
    let response = client.post(&url)
        .header("Authorization", format!("Bearer {}", redis_token))
        .send().await?;
    
    if !response.status().is_success() {
        return Err(Error::RustError("Failed to add user to set".to_string()));
    }
    Ok(())
}

async fn get_all_user_ids(env: &Env) -> Result<Vec<i64>> {
    let redis_url = env.var("REDIS_URL")?.to_string();
    let redis_token = env.var("REDIS_TOKEN")?.to_string();
    let client = Client::new();
    let url = format!("{}/smembers/users", redis_url);
    
    let response = client.get(&url)
        .header("Authorization", format!("Bearer {}", redis_token))
        .send().await?;
    
    if !response.status().is_success() {
        return Err(Error::RustError("Failed to fetch user IDs".to_string()));
    }
    
    let data: serde_json::Value = response.json().await?;
    let user_ids: Vec<i64> = data["result"]
        .as_array()
        .unwrap_or(&vec![])
        .iter()
        .filter_map(|v| v.as_str().and_then(|s| s.parse().ok()))
        .collect();
    Ok(user_ids)
}

#[event(fetch)]
async fn main(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    console_error_panic_hook::set_once();

    let router = Router::new();

    router
        .post_async("/webhook", |mut req, ctx| async move {
            let update: TelegramMessage = req.json().await?;
            if let Some(message) = update.message {
                if let Some(text) = message.text {
                    let chat_id = message.chat.id;
                    let user_id = message.from.id;
                    let username = message.from.username.unwrap_or("User".to_string());
                    
                    if text == "/start" {
                        let welcome_message = format!(
                            "*Halo, {}!* Selamat datang \n\n\
                            ID Pengguna kamu: {}. \n\n\
                            Tolong jaga sikap, Jangan Sok Pro. \n\n\
                            Yang melanggar Akan Terkena Blokir Dan Tidak Akan Bisa Login Dll 😝. \n\n\
                            Catat baik-baik🖕🖕",
                            username, user_id
                        );
                        send_telegram_message(chat_id, welcome_message, &ctx.env).await?;
                    }
                }
            }
            Response::ok("ok")
        })
        .post_async("/register", |mut req, ctx| async move {
            let user: RegisterUser = req.json().await?;
            let user_id = user.user_id;
            
            if get_redis_data(user_id, &ctx.env).await.is_ok() {
                return Response::error("User already exists", 400);
            }
            
            let username = verify_telegram_user(user_id, &ctx.env).await?;
            let api_key = generate_api_key();
            let user_data = User {
                user_id,
                username,
                api_key: api_key.clone(),
                created_at: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
                    .to_string(),
                is_blocked: false,
                is_verified: false,
            };
            
            let otp = generate_otp();
            let otp_message = format!(
                "*Registration Successful!* \n\n\
                *Your OTP*: `{}` \n\
                Please verify this OTP to activate your account and login. \n\
                *Expires in 5 minutes*.", otp
            );
            
            send_telegram_message(user_id, otp_message, &ctx.env).await?;
            set_redis_data(user_id, &serde_json::to_string(&user_data)?, &ctx.env).await?;
            add_user_to_set(user_id, &ctx.env).await?;
            store_otp_to_redis(user_id, &otp, &ctx.env).await?;
            
            Response::from_json(&json!({
                "message": "User registered. Please verify OTP to activate account.",
                "api_key": api_key
            }))
        })
        .post_async("/login", |mut req, ctx| async move {
            let login: LoginUser = req.json().await?;
            let user_id = login.user_id;
            
            let user_data = get_redis_data(user_id, &ctx.env).await
                .map_err(|_| Error::RustError("User not found".to_string()))?;
            let user: User = serde_json::from_str(&user_data)?;
            
            if user.is_blocked {
                return Response::error("User is blocked", 403);
            }
            
            let otp = generate_otp();
            store_otp_to_redis(user_id, &otp, &ctx.env).await?;
            let otp_message = if !user.is_verified {
                format!(
                    "*Verification OTP Generated!* \n\n\
                    *Your OTP*: `{}` \n\
                    Please verify this OTP to activate your account and login. \n\
                    *Expires in 5 minutes*.", otp
                )
            } else {
                format!(
                    "*Login OTP Generated!* \n\n\
                    *Your OTP*: `{}` \n\
                    *Expires in 5 minutes*.", otp
                )
            };
            
            send_telegram_message(user_id, otp_message, &ctx.env).await?;
            Response::from_json(&json!({
                "message": "OTP sent successfully. Please verify OTP to login.",
                "api_key": user.api_key
            }))
        })
        .post_async("/request_otp", |mut req, ctx| async move {
            let otp_request: OTPRequest = req.json().await?;
            let user_id = otp_request.user_id;
            
            let user = verify_api_key(user_id, &otp_request.api_key, &ctx.env).await?;
            
            let otp = generate_otp();
            store_otp_to_redis(user_id, &otp, &ctx.env).await?;
            let otp_message = if !user.is_verified {
                format!(
                    "*Verification OTP Generated!* \n\n\
                    *Your OTP*: `{}` \n\
                    Please verify this OTP to activate your account and login. \n\
                    *Expires in 5 minutes*.", otp
                )
            } else {
                format!(
                    "*New OTP Generated!* \n\n\
                    *Your OTP*: `{}` \n\
                    *Expires in 5 minutes*.", otp
                )
            };
            
            send_telegram_message(user_id, otp_message, &ctx.env).await?;
            Response::ok("OTP sent successfully")
        })
        .post_async("/verify_otp", |mut req, ctx| async move {
            let otp_verify: OTPVerify = req.json().await?;
            let user_id = otp_verify.user_id;
            
            let user_data = get_redis_data(user_id, &ctx.env).await
                .map_err(|_| Error::RustError("User not found".to_string()))?;
            let mut user: User = serde_json::from_str(&user_data)?;
            
            let stored_otp = retrieve_otp_from_redis(user_id, &ctx.env).await?;
            if stored_otp.is_none() || stored_otp.unwrap() != otp_verify.otp {
                return Response::error("Invalid OTP or expired", 400);
            }
            
            user.is_verified = true;
            set_redis_data(user_id, &serde_json::to_string(&user)?, &ctx.env).await?;
            
            let otp_verified_message = format!(
                "*OTP Verified Successfully!* \n\n\
                Welcome back, {}! \n\
                You are now logged in.", user.username
            );
            send_telegram_message(user_id, otp_verified_message, &ctx.env).await?;
            
            Response::from_json(&json!({
                "message": "OTP verified successfully",
                "api_key": user.api_key
            }))
        })
        .post_async("/broadcast", |mut req, ctx| async move {
            let broadcast: BroadcastRequest = req.json().await?;
            verify_admin_api_key(&broadcast.api_key, &ctx.env).await?;
            
            let user_ids = get_all_user_ids(&ctx.env).await?;
            let mut users = vec![];
            for user_id in user_ids {
                if let Ok(user_data) = get_redis_data(user_id, &ctx.env).await {
                    if let Ok(user) = serde_json::from_str(&user_data) {
                        users.push(user);
                    }
                }
            }
            
            if users.is_empty() {
                return Response::error("No users found", 404);
            }
            
            let broadcast_message = format!(
                "*Broadcast Message* \n\n\
                {}. \n\n", broadcast.message
            );
            
            let mut failed_users = vec![];
            for user in &users {
                if let Err(e) = send_telegram_message(user.user_id, broadcast_message.clone(), &ctx.env).await {
                    failed_users.push(user.user_id);
                    console_log!("Failed to send broadcast to user {}: {}", user.user_id, e);
                }
            }
            
            if !failed_users.is_empty() {
                Response::from_json(&json!({
                    "message": format!("Broadcast sent to {}/{} users. Failed for user IDs: {:?}", 
                        users.len() - failed_users.len(), users.len(), failed_users)
                }))
            } else {
                Response::from_json(&json!({
                    "message": format!("Broadcast sent successfully to {} users", users.len())
                }))
            }
        })
        .post_async("/users", |mut req, ctx| async move {
            let admin_request: AdminRequest = req.json().await?;
            verify_admin_api_key(&admin_request.api_key, &ctx.env).await?;
            
            let user_ids = get_all_user_ids(&ctx.env).await?;
            let mut users = vec![];
            for user_id in user_ids {
                if let Ok(user_data) = get_redis_data(user_id, &ctx.env).await {
                    if let Ok(user) = serde_json::from_str(&user_data) {
                        users.push(user);
                    }
                }
            }
            
            Response::from_json(&json!({ "users": users }))
        })
        .post_async("/block_user", |mut req, ctx| async move {
            let block: BlockUser = req.json().await?;
            verify_admin_api_key(&block.api_key, &ctx.env).await?;
            
            let user_data = get_redis_data(block.user_id, &ctx.env).await
                .map_err(|_| Error::RustError("User not found".to_string()))?;
            let mut user: User = serde_json::from_str(&user_data)?;
            
            user.is_blocked = block.block;
            set_redis_data(block.user_id, &serde_json::to_string(&user)?, &ctx.env).await?;
            
            let status = if block.block { "blocked" } else { "unblocked" };
            let block_message = if let Some(custom_message) = block.custom_message {
                format!(
                    "*Account Status Update* \n\n\
                    Your account has been *{}*. \n\
                    *Message from Admin*: {}. \n", status, custom_message
                )
            } else {
                format!(
                    "*Account Status Update* \n\n\
                    Your account has been *{}*. \n", status
                )
            };
            
            send_telegram_message(block.user_id, block_message, &ctx.env).await?;
            Response::ok(format!("User {} successfully", status))
        })
        .post_async("/user", |mut req, ctx| async move {
            let get_user: GetUser = req.json().await?;
            let user_data = match verify_api_key(get_user.user_id, &get_user.api_key, &ctx.env).await {
                Ok(user) => user,
                Err(_) => {
                    verify_admin_api_key(&get_user.api_key, &ctx.env).await?;
                    let data = get_redis_data(get_user.user_id, &ctx.env).await
                        .map_err(|_| Error::RustError("User not found".to_string()))?;
                    serde_json::from_str(&data)?
                }
            };
            
            Response::from_json(&user_data)
        })
        .run(req, env).await
}
