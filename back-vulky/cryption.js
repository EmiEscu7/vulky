import crypto from 'crypto';
import dotenv from 'dotenv';
dotenv.config();

// Clave secreta (debe ser de 32 bytes para AES-256)
const ENCRYPTION_KEY = Buffer.from(process.env.ENCRYPTION_KEY, 'hex');
const IV_LENGTH = 16; // Para AES, el IV debe ser de 16 bytes

export function cryptPass(pass) {
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
    let ecnrypted = cipher.update(pass, 'utf-8', 'hex');
    ecnrypted += cipher.final('hex');

    return iv.toString('hex') + ':' + ecnrypted;
}

export function decrypt(text) {
    const textParts = text.split(':');
    const iv = Buffer.from(textParts[0], 'hex');
    const encryptedText = Buffer.from(textParts[1], 'hex');
    const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
    let decrypted = decipher.update(encryptedText, 'hex', 'utf-8');
    decrypted += decipher.final('utf-8');
    return decrypted;
}

export function hashPass(pass) {
    return crypto.createHash('sha256').update(pass).digest('hex');
}