package com.example.tom.encrypt_message;

import android.content.Context;
import android.content.SharedPreferences;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;

import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
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
        Button decryptButton = (Button) findViewById(R.id.decrypt);

        encryptButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                byte[] message = ((EditText) findViewById(R.id.message)).getText().toString().getBytes();
                byte[] encrypted = encrypt(pair.getPrivate(), message);
                ((TextView)findViewById(R.id.encryptedMessage)).setText(encrypted.toString());
            }
        });
    }

    public static KeyPair generate() {
        try {
            SecureRandom sr = new SecureRandom();
            RSAKeyGenParameterSpec spec = new RSAKeyGenParameterSpec(KEY_SIZE, RSAKeyGenParameterSpec.F4);
            KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA", "BC");
            gen.initialize(spec, sr);
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

    public byte[] encrypt(Key privKey, byte[] plaintext) {
        try {
            Cipher cipher = Cipher.getInstance("RSA/NONE/OAEPWithSHA256AndMGF1Padding", "BC");
            cipher.init(Cipher.ENCRYPT_MODE, privKey);
            cipher.update(plaintext);
            return cipher.doFinal();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
}