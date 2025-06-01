// frontend/src/workers/encryption.worker.js
import CryptoJS from 'crypto-js';

// --- 加密常量和辅助函数 (与 cryptoService.js 中定义一致) ---
const SALT_SIZE_BYTES = 16;
const IV_SIZE_BYTES = 16;
const PBKDF2_ITERATIONS = 100000; // 保持高迭代次数以确保安全
const DERIVED_KEY_SIZE_BITS = 512;
const AES_KEY_SIZE_BITS = 256;
const HMAC_KEY_SIZE_BITS = 256;

function wordArrayToBase64(wordArray) {
  return CryptoJS.enc.Base64.stringify(wordArray);
}

// --- 加密核心逻辑 ---
function performEncryption(text, password, expiryTimestamp = null) {
  try {
    const salt = CryptoJS.lib.WordArray.random(SALT_SIZE_BYTES);
    const derivedKey = CryptoJS.PBKDF2(password, salt, {
      keySize: DERIVED_KEY_SIZE_BITS / 32,
      iterations: PBKDF2_ITERATIONS,
      hasher: CryptoJS.algo.SHA256
    });

    const aesKey = CryptoJS.lib.WordArray.create(derivedKey.words.slice(0, AES_KEY_SIZE_BITS / 32));
    const hmacKey = CryptoJS.lib.WordArray.create(derivedKey.words.slice(AES_KEY_SIZE_BITS / 32));
    const payloadToEncrypt = JSON.stringify({ message: text, expiry: expiryTimestamp });
    const iv = CryptoJS.lib.WordArray.random(IV_SIZE_BYTES);
    const encrypted = CryptoJS.AES.encrypt(payloadToEncrypt, aesKey, {
      iv: iv, padding: CryptoJS.pad.Pkcs7, mode: CryptoJS.mode.CBC
    });
    const ciphertext = encrypted.ciphertext;
    const dataToMac = iv.clone().concat(ciphertext);
    const mac = CryptoJS.HmacSHA256(dataToMac, hmacKey);
    
    // 返回组合后的加密字符串
    return `${wordArrayToBase64(salt)}.${wordArrayToBase64(iv)}.${wordArrayToBase64(ciphertext)}.${wordArrayToBase64(mac)}`;
  } catch (error) {
    console.error("Worker encryption error:", error);
    // 通过抛出错误，让主线程的 Worker 错误处理捕获
    throw new Error("Encryption failed in worker: " + (error.message || "Unknown error"));
  }
}

// --- Worker 消息监听与响应 ---
self.onmessage = function(event) {
  const { id, text, password, expiryTimestamp } = event.data;
  try {
    const encryptedPayload = performEncryption(text, password, expiryTimestamp);
    // 将结果和原始请求ID一起发送回主线程
    self.postMessage({ id, encryptedPayload });
  } catch (error) {
    // 将错误信息和原始请求ID一起发送回主线程
    self.postMessage({ id, error: error.message });
  }
};

