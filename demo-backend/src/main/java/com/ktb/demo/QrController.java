package com.ktb.demo;

import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Map;

import javax.imageio.ImageIO;

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.http.CacheControl;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.EncodeHintType;
import com.google.zxing.WriterException;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel;

/**
 * วาด otpauth:// URI เป็น QR (PNG) ด้วย zxing
 * ใช้ POST + no-store เพื่อไม่ให้ secret ไปอยู่ใน URL / log / cache ของ proxy
 * รับเฉพาะ otpauth://totp/ เพื่อไม่ให้ endpoint นี้กลายเป็นตัวสร้าง QR ทั่วไป
 */
@RestController
@RequestMapping("/api/auth")
public class QrController {

    private static final int SIZE = 256;

    private final RateLimiter limiter;

    public QrController(RateLimiter limiter) {
        this.limiter = limiter;
    }

    @PostMapping(value = "/qr", produces = MediaType.IMAGE_PNG_VALUE)
    public ResponseEntity<byte[]> qr(@RequestBody Map<String, String> body, HttpServletRequest http) throws IOException {
        // endpoint นี้เปิดโดยไม่ต้อง login (ใช้ตอน enroll) จึงจำกัดต่อ IP กันถูกใช้เปลืองทรัพยากร
        if (!limiter.tryAcquire("qr:" + http.getRemoteAddr())) {
            throw new ResponseStatusException(org.springframework.http.HttpStatus.TOO_MANY_REQUESTS, "Too many requests");
        }
        String text = body.get("text");
        if (text == null || text.length() > 512 || !text.startsWith("otpauth://totp/")) {
            throw new ResponseStatusException(org.springframework.http.HttpStatus.BAD_REQUEST, "Invalid text");
        }
        BitMatrix m;
        try {
            m = new QRCodeWriter().encode(text, BarcodeFormat.QR_CODE, SIZE, SIZE,
                    Map.of(EncodeHintType.ERROR_CORRECTION, ErrorCorrectionLevel.M,
                           EncodeHintType.MARGIN, 2));
        } catch (WriterException e) {
            throw new ResponseStatusException(org.springframework.http.HttpStatus.BAD_REQUEST, "Cannot encode");
        }
        BufferedImage img = new BufferedImage(m.getWidth(), m.getHeight(), BufferedImage.TYPE_INT_RGB);
        for (int x = 0; x < m.getWidth(); x++) {
            for (int y = 0; y < m.getHeight(); y++) {
                img.setRGB(x, y, m.get(x, y) ? 0x000000 : 0xFFFFFF);
            }
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ImageIO.write(img, "png", out);
        return ResponseEntity.ok().cacheControl(CacheControl.noStore()).body(out.toByteArray());
    }
}
