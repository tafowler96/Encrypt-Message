package com.example.tom.encrypt_message;

import android.content.Context;
import android.content.SharedPreferences;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Base64;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;

import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAKeyGenParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;

public class MainActivity extends AppCompatActivity {

    private static final int KEY_SIZE = 2048;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        final KeyPair pair = MainActivity.generate();
        writeKeyPairToPreferences(pair);

        Button encryptButton = (Button) findViewById(R.id.encrypt);
        final Button decryptButton = (Button) findViewById(R.id.decrypt);

        encryptButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                byte[] message = ((EditText) findViewById(R.id.message)).getText().toString().getBytes();
                byte[] encrypted = encrypt(pair.getPublic(), message);
                byte[] encoded = Base64.encode(encrypted, Base64.DEFAULT);
                ((TextView)findViewById(R.id.encryptedMessage)).setText(bytesToHex(encoded));
            }
        });
        decryptButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                String message = ((TextView) findViewById(R.id.encryptedMessage)).getText().toString();
                byte[] decoded = Base64.decode(message, Base64.DEFAULT);
                byte[] decrypted = decrypt(pair.getPrivate(), decoded);
                ((TextView)findViewById(R.id.encryptedMessage)).setText(new String(decrypted));
            }
        });
    }

    private String bytesToHex(byte[] bytes) {
        StringBuffer result = new StringBuffer();
        for (byte b : bytes) result.append(Integer.toString((b & 0xff) + 0x100, 16).substring(1));
        return result.toString();
    }

    private byte[] decrypt(PrivateKey privKey, byte[] message) {
        try {
            Cipher cipher = Cipher.getInstance("RSA/NONE/OAEPWithSHA256AndMGF1Padding", "BC");
            cipher.init(Cipher.DECRYPT_MODE, privKey);
//            cipher.update(plaintext);
            return cipher.doFinal(message);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static KeyPair generate() {
        try {
            SecureRandom sr = new SecureRandom();
            RSAKeyGenParameterSpec spec = new RSAKeyGenParameterSpec(KEY_SIZE, RSAKeyGenParameterSpec.F4);
            KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA", "BC");
            gen.initialize(KEY_SIZE);
            KeyPair pair = gen.generateKeyPair();
//            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(pair.getPrivate().getEncoded());
            return pair;
        } catch (Exception e){
            throw new RuntimeException(e);
        }
    }

    public void writeKeyPairToPreferences(KeyPair pair) {
        SharedPreferences preferences = getPreferences(Context.MODE_PRIVATE);
        SharedPreferences.Editor editor = preferences.edit();
        editor.putString("publicKey", pair.getPublic().toString());
        editor.putString("privateKey", pair.getPrivate().toString());
    }

    private byte[] encrypt(Key pubKey, byte[] plaintext) {
        try {
            Cipher cipher = Cipher.getInstance("RSA/NONE/OAEPWithSHA256AndMGF1Padding", "BC");
            cipher.init(Cipher.ENCRYPT_MODE, pubKey);
            Log.v("Format", pubKey.getFormat());
//            cipher.update(plaintext);
            return cipher.doFinal(plaintext);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
}