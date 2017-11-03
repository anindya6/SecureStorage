package com.example.anindyabhandari.newapp;

import android.content.Intent;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Log;
import android.widget.TextView;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;

public class DisplayMessageActivity extends AppCompatActivity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_display_message);
        // Get the Intent that started this activity and extract the string
        Intent intent = getIntent();
        String message = intent.getStringExtra(MainActivity.EXTRA_MESSAGE);
        //adding this part, feel free to change
        String alias = "Hello";
        try{
            //final KeyGenerator keyGenerator = KeyGenerator
                    //.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");//ANDROID_KEY_STORE);

            //final KeyGenParameterSpec keyGenParameterSpec = new KeyGenParameterSpec.Builder(alias,
                    //KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                    //.setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    //.setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    //.build();

            //keyGenerator.init(keyGenParameterSpec);
            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);
            //char[] pa={'H','I'};
            //KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection(pa);
            SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
            byte[] salt = new byte[32];
            sr.nextBytes(salt);
            char[] pass = {'H','E','L','L','O'};
            final SecretKey secretKey = generateKey(pass,salt);//keyGenerator.generateKey();
            //KeyStore.SecretKeyEntry sk = new KeyStore.SecretKeyEntry(secretKey);
            //keyStore.setEntry(alias, sk, null);
            final Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);

            byte[] iv = cipher.getIV();

            byte[] encryption = cipher.doFinal(message.getBytes("UTF-8"));
            String str = new String(encryption, "UTF-8");

            //final KeyStore.SecretKeyEntry secretKeyEntry = (KeyStore.SecretKeyEntry) keyStore.getEntry(alias, null);

            //final SecretKey secretKey2 = secretKeyEntry.getSecretKey();
            //stop here
            // Capture the layout's TextView and set the string as its text
            TextView textView = (TextView) findViewById(R.id.textView2);
            //textView.setText(message);
            textView.setText(str);
            final Cipher cipher2 = Cipher.getInstance("AES/GCM/NoPadding");
            final GCMParameterSpec spec = new GCMParameterSpec(128, iv);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, spec);
            final byte[] decodedData = cipher.doFinal(encryption);
            final String unencrypted = new String(decodedData, "UTF-8");
            TextView textView2 = (TextView) findViewById(R.id.textView);
            //textView.setText(message);
            textView2.setText(unencrypted);
        }
        catch (Exception e)
        {
            TextView textView = (TextView) findViewById(R.id.textView);
            //textView.setText(message);
            textView.setText("Something failed :(");
            return;
        }
    }
    public static SecretKey generateKey(char[] passphraseOrPin, byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException
    {
        // Number of PBKDF2 hardening rounds to use. Larger values increase
        // computation time. You should select a value that causes computation
        // to take >100ms.
        final int iterations = 1000;

        // Generate a 256-bit key
        final int outputKeyLength = 256;

        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");//can also use SHA256 or SHA224
        KeySpec keySpec = new PBEKeySpec(passphraseOrPin, salt, iterations, outputKeyLength);
        SecretKey secretKey = secretKeyFactory.generateSecret(keySpec);
        return secretKey;
    }
}
