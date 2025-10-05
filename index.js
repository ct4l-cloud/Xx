// index.js
// Cloudflare Worker untuk Telegram Bot dengan Cloudflare KV
// Deploy: npm init -y && npm i && wrangler deploy
// Pastikan secrets diatur via: wrangler secret put TELEGRAM_BOT_TOKEN, ADMIN_API_KEY

export default {
  async fetch(request, env, ctx) {
    // Variabel dari env
    const TELEGRAM_BOT_TOKEN = env.TELEGRAM_BOT_TOKEN;
    const TELEGRAM_API_URL = `https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}`;
    const ADMIN_API_KEY = env.ADMIN_API_KEY;

    // Helper Functions
    async function sendTelegramMessage(chatId, text) {
      try {
        const response = await fetch(`${TELEGRAM_API_URL}/sendMessage`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            chat_id: chatId,
            text,
            parse_mode: 'Markdown'
          })
        });
        if (!response.ok) {
          const errorData = await response.json();
          throw new Error(`HTTP ${response.status}: ${errorData.description || response.statusText}`);
        }
      } catch (error) {
        console.error('Failed to send Telegram message:', error);
        throw new Error(`Failed to send Telegram message: ${error.message}`);
      }
    }

    function generateOTP() {
      let otp = '';
      for (let i = 0; i < 6; i++) {
        otp += Math.floor(Math.random() * 16).toString(16);
      }
      return otp.toUpperCase();
    }

    function generateAPIKey() {
      let key = '';
      for (let i = 0; i < 32; i++) {
        key += Math.floor(Math.random() * 16).toString(16);
      }
      return key;
    }

    async function verifyAPIKey(userId, apiKey) {
      const userData = await env.KV_USERS.get(`user:${userId}`);
      if (!userData) {
        throw new Error('User not found', { status: 404 });
      }
      const user = JSON.parse(userData);
      if (user.api_key !== apiKey) {
        throw new Error('Invalid API Key', { status: 401 });
      }
      if (user.is_blocked) {
        throw new Error('User is blocked', { status: 403 });
      }
      if (!user.is_verified) {
        throw new Error('User is not verified. Please verify OTP.', { status: 403 });
      }
      return user;
    }

    async function verifyAdminAPIKey(apiKey) {
      if (apiKey !== ADMIN_API_KEY) {
        throw new Error('Invalid Admin API Key', { status: 401 });
      }
    }

    async function checkUserStatus(userId) {
      const userData = await env.KV_USERS.get(`user:${userId}`);
      if (!userData) {
        throw new Error('User not found', { status: 404 });
      }
      const user = JSON.parse(userData);
      if (user.is_blocked) {
        throw new Error('User is blocked', { status: 403 });
      }
      return user;
    }

    async function verifyTelegramUser(userId) {
      try {
        const response = await fetch(`${TELEGRAM_API_URL}/getChat?chat_id=${userId}`);
        if (!response.ok) {
          const errorData = await response.json();
          throw new Error(errorData.description || 'Unknown error', { status: 400 });
        }
        const data = await response.json();
        if (!data.ok) {
          throw new Error(data.description || 'Unknown error', { status: 400 });
        }
        const chat = data.result;
        if (chat.type !== 'private') {
          throw new Error('Invalid chat type', { status: 400 });
        }
        return chat.username || `User_${userId}`;
      } catch (error) {
        if (error.status) {
          throw error;
        }
        throw new Error('Invalid Telegram user ID or network error', { status: 400 });
      }
    }

    async function storeOTP(userId, otp) {
      await env.KV_OTP.put(`otp:${userId}`, otp, { expirationTtl: 300 }); // 5 menit TTL
    }

    async function retrieveOTP(userId) {
      return await env.KV_OTP.get(`otp:${userId}`);
    }

    async function deleteOTP(userId) {
      await env.KV_OTP.delete(`otp:${userId}`);
    }

    // Webhook Handler
    async function handleWebhook(update) {
      if (update.message && update.message.text) {
        const message = update.message;
        const chatId = message.chat.id;
        const text = message.text;
        const userId = message.from.id;
        const username = message.from.username || 'User';

        if (text === '/start') {
          const welcomeMessage = `*🌐 Halo, ${username}!* Selamat datang\n\n` +
            `👾 ID Pengguna kamu: ${userId}.\n\n` +
            `🔁 Tolong jaga sikap, Jangan Sok Pro.\n\n` +
            `☕ Yang melanggar Akan Terkena Blokir Dan Tidak Akan Bisa Login Dll 😝.\n\n` +
            `🔧 Catat baik-baik🖕🖕`;
          await sendTelegramMessage(chatId, welcomeMessage);
        }
      }
      return { status: 'ok' };
    }

    // API Handlers
    async function handleRegister(body) {
      const { user_id: userId } = body;
      const existingUser = await env.KV_USERS.get(`user:${userId}`);
      if (existingUser) {
        throw new Error('User already exists', { status: 400 });
      }

      const username = await verifyTelegramUser(userId);
      const apiKey = generateAPIKey();
      const userData = {
        user_id: userId,
        username,
        api_key: apiKey,
        created_at: new Date().toISOString(),
        is_blocked: false,
        is_verified: false
      };

      const otp = generateOTP();
      const otpMessage = `🎉 *Registration Successful!*\n\n` +
        `🔐 *Your OTP*: \`${otp}\`\n` +
        `Please verify this OTP to activate your account and login.\n` +
        `⏳ *Expires in 5 minutes*.`;
      await sendTelegramMessage(userId, otpMessage);

      await env.KV_USERS.put(`user:${userId}`, JSON.stringify(userData));
      await storeOTP(userId, otp);

      return { message: 'User registered. Please verify OTP to activate account.', api_key: apiKey };
    }

    async function handleLogin(body) {
      const { user_id: userId } = body;
      const userData = await env.KV_USERS.get(`user:${userId}`);
      if (!userData) {
        throw new Error('User not found', { status: 404 });
      }
      const user = JSON.parse(userData);
      if (user.is_blocked) {
        throw new Error('User is blocked', { status: 403 });
      }

      const otp = generateOTP();
      await storeOTP(userId, otp);
      let otpMessage = `🔐 *Login OTP Generated!*\n\n` +
        `🔑 *Your OTP*: \`${otp}\`\n` +
        `⏳ *Expires in 5 minutes*.`;
      if (!user.is_verified) {
        otpMessage = `🔐 *Verification OTP Generated!*\n\n` +
          `🔑 *Your OTP*: \`${otp}\`\n` +
          `Please verify this OTP to activate your account and login.\n` +
          `⏳ *Expires in 5 minutes*.`;
      }

      await sendTelegramMessage(userId, otpMessage);
      return { message: 'OTP sent successfully. Please verify OTP to login.', api_key: user.api_key };
    }

    async function handleOTPRequest(body) {
      const { user_id: userId, api_key: apiKey } = body;
      const userData = await env.KV_USERS.get(`user:${userId}`);
      if (!userData) {
        throw new Error('User not found', { status: 404 });
      }
      const user = JSON.parse(userData);
      if (user.api_key !== apiKey) {
        throw new Error('Invalid API Key', { status: 401 });
      }
      if (user.is_blocked) {
        throw new Error('User is blocked', { status: 403 });
      }

      const otp = generateOTP();
      await storeOTP(userId, otp);
      let otpMessage = `🔐 *New OTP Generated!*\n\n` +
        `🔑 *Your OTP*: \`${otp}\`\n` +
        `⏳ *Expires in 5 minutes*.`;
      if (!user.is_verified) {
        otpMessage = `🔐 *Verification OTP Generated!*\n\n` +
          `🔑 *Your OTP*: \`${otp}\`\n` +
          `Please verify this OTP to activate your account and login.\n` +
          `⏳ *Expires in 5 minutes*.`;
      }

      await sendTelegramMessage(userId, otpMessage);
      return { message: 'OTP sent successfully' };
    }

    async function handleVerifyOTP(body) {
      const { user_id: userId, otp } = body;
      const userData = await env.KV_USERS.get(`user:${userId}`);
      if (!userData) {
        throw new Error('User not found', { status: 404 });
      }
      let user;
      try {
        user = JSON.parse(userData);
      } catch (e) {
        throw new Error('Internal server error: Invalid user data format', { status: 500 });
      }

      const storedOTP = await retrieveOTP(userId);
      if (!storedOTP) {
        throw new Error('OTP not found or expired. Please request a new OTP.', { status: 400 });
      }
      if (storedOTP !== otp) {
        throw new Error('Invalid OTP', { status: 400 });
      }

      user.is_verified = true;
      await env.KV_USERS.put(`user:${userId}`, JSON.stringify(user));
      await deleteOTP(userId);

      const otpVerifiedMessage = `✅ *OTP Verified Successfully!*\n\n` +
        `🎉 Welcome back, ${user.username}!\n` +
        `📌 You are now logged in.`;
      try {
        await sendTelegramMessage(userId, otpVerifiedMessage);
      } catch (e) {
        console.error(`Failed to send verification message to ${userId}:`, e);
      }

      return { message: 'OTP verified successfully', api_key: user.api_key };
    }

    async function handleBroadcast(body) {
      const { api_key: apiKey, message } = body;
      await verifyAdminAPIKey(apiKey);

      // List semua user dari KV (menggunakan list untuk iterasi)
      const keys = await env.KV_USERS.list({ prefix: 'user:' });
      const users = [];
      for (const key of keys.keys) {
        const userData = await env.KV_USERS.get(key.name);
        if (userData) {
          try {
            users.push(JSON.parse(userData));
          } catch (e) {
            console.error(`Error decoding user data for ${key.name}:`, e);
          }
        }
      }

      if (!users.length) {
        throw new Error('No users found', { status: 404 });
      }

      const escapedMessage = message.replace(/\*/g, '\\*').replace(/`/g, '\\`').replace(/_/g, '\\_');
      const broadcastMessage = `📢 *Broadcast Message*\n\n` +
        `${escapedMessage}\n\n`;

      const failedUsers = [];
      for (const user of users) {
        try {
          await sendTelegramMessage(user.user_id, broadcastMessage);
        } catch (e) {
          console.error(`Failed to send broadcast to ${user.user_id}:`, e);
          failedUsers.push(user.user_id);
        }
      }

      if (failedUsers.length) {
        return {
          message: `Broadcast sent to ${users.length - failedUsers.length}/${users.length} users. Failed for user IDs: ${failedUsers.join(', ')}`
        };
      }
      return { message: `Broadcast sent successfully to ${users.length} users` };
    }

    async function handleListUsers(body) {
      const { api_key: apiKey } = body;
      await verifyAdminAPIKey(apiKey);

      const keys = await env.KV_USERS.list({ prefix: 'user:' });
      const users = [];
      for (const key of keys.keys) {
        const userData = await env.KV_USERS.get(key.name);
        if (userData) {
          users.push(JSON.parse(userData));
        }
      }
      return { users };
    }

    async function handleBlockUser(body) {
      const { user_id: userId, block, api_key: apiKey, custom_message: customMessage } = body;
      await verifyAdminAPIKey(apiKey);

      const userData = await env.KV_USERS.get(`user:${userId}`);
      if (!userData) {
        throw new Error('User not found', { status: 404 });
      }
      const user = JSON.parse(userData);
      user.is_blocked = block;
      await env.KV_USERS.put(`user:${userId}`, JSON.stringify(user));

      const status = block ? 'blocked' : 'unblocked';
      let blockMessage;
      if (customMessage) {
        blockMessage = `⚠️ *Account Status Update*\n\n` +
          `Your account has been *${status}*.\n` +
          `📩 *Message from Admin*: ${customMessage}.\n`;
      } else {
        blockMessage = `⚠️ *Account Status Update*\n\n` +
          `Your account has been *${status}*.\n`;
      }

      await sendTelegramMessage(userId, blockMessage);
      return { message: `User ${status} successfully` };
    }

    async function handleGetUser(body) {
      const { user_id: userId, api_key: apiKey } = body;
      try {
        await verifyAPIKey(userId, apiKey);
      } catch (e) {
        if (e.message === 'Invalid API Key' && apiKey === ADMIN_API_KEY) {
          await verifyAdminAPIKey(apiKey);
        } else {
          throw e;
        }
      }

      const userData = await env.KV_USERS.get(`user:${userId}`);
      if (!userData) {
        throw new Error('User not found', { status: 404 });
      }
      return JSON.parse(userData);
    }

    // Main Request Handler
    try {
      if (request.method !== 'POST') {
        return new Response('Method not allowed', { status: 405 });
      }

      let body;
      try {
        body = await request.json();
      } catch (e) {
        return new Response('Invalid JSON', { status: 400 });
      }

      const url = new URL(request.url);
      const path = url.pathname;

      let result;
      switch (path) {
        case '/webhook':
          result = await handleWebhook(body);
          break;
        case '/register':
          result = await handleRegister(body);
          break;
        case '/login':
          result = await handleLogin(body);
          break;
        case '/request_otp':
          result = await handleOTPRequest(body);
          break;
        case '/verify_otp':
          result = await handleVerifyOTP(body);
          break;
        case '/broadcast':
          result = await handleBroadcast(body);
          break;
        case '/users':
          result = await handleListUsers(body);
          break;
        case '/block_user':
          result = await handleBlockUser(body);
          break;
        case '/user':
          result = await handleGetUser(body);
          break;
        default:
          return new Response('Not found', { status: 404 });
      }

      return new Response(JSON.stringify(result), {
        status: 200,
        headers: { 'Content-Type': 'application/json' }
      });
    } catch (error) {
      console.error('Error in handler:', error);
      const status = error.status || 500;
      return new Response(JSON.stringify({ detail: error.message }), {
        status,
        headers: { 'Content-Type': 'application/json' }
      });
    }
  }
};
