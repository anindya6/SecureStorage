package com.example.anindyabhandari.newapp;

import android.content.Intent;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.security.keystore.KeyProtection;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.EditText;
import android.widget.TextView;

import java.io.FileInputStream;
import java.io.FileOutputStream;
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
import javax.crypto.spec.SecretKeySpec;

public class DisplayMessageActivity extends AppCompatActivity {
    public static final String EXTRA_MESSAGE = "something.somewhere";//new String [2];
    public byte [] iv_f;
    public byte [] ct_pass;
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
            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");//KeyStore.getDefaultType());

            char[] password={'p','a','s','s'};
            /*
            try (FileInputStream fis = new FileInputStream("commstore")) {
                keyStore.load(fis, password);
            }
            catch(Exception e)
            {
                keyStore.load(null, password);
            }*/
            keyStore.load(null);//,password);
            KeyStore.ProtectionParameter pp = new KeyStore.PasswordProtection(password);
            //KeyStore.PasswordProtection pp = new KeyStore.PasswordProtection(password);
            //KeyStore.PasswordProtection pp = new KeyProtection(password);
            SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
            byte[] salt = new byte[32];
            sr.nextBytes(salt);
            char[] pass = {'H','E','L','L','O'};
            final SecretKey secretKey = generateKey(pass,salt);//keyGenerator.generateKey();
            //try {
                byte[] temp = secretKey.getEncoded();
                SecretKey key2 = new SecretKeySpec(temp, 0, temp.length, "AES");
                //t=secretKey;
                KeyStore.SecretKeyEntry sk = new KeyStore.SecretKeyEntry(key2);
            //}
            //catch(Exception e){Log.e("YOUR_APP_LOG_TAG_1", "I got an error", e);}
            //try{
                //keyStore.setEntry(alias, sk, KeyProtection.Builder(KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT).build());//pp);
                keyStore.setEntry(
                        alias,sk,
                        //new KeyStore.SecretKeyEntry(secretKey),//null);
                        new KeyProtection.Builder(KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                                .build());
            //}
            //catch(Exception e){Log.e("YOUR_APP_LOG_TAG_2", "I got an error", e);}
            final Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, key2);

            byte[] iv = cipher.getIV();
            iv_f=iv;
            TextView textView0 = (TextView) findViewById(R.id.textView4);
            textView0.setText(iv.toString());
            byte[] encryption = cipher.doFinal(message.getBytes("UTF-8"));
            ct_pass=encryption;
            String str = new String(encryption, "UTF-8");
            //try {
                final KeyStore.SecretKeyEntry secretKeyEntry = (KeyStore.SecretKeyEntry) keyStore.getEntry(alias, null);//pp);
                //final KeyStore.Entry entry = keyStore.getEntry(alias,null);
                final SecretKey secretKey2 = secretKeyEntry.getSecretKey();
            //}
            //catch(Exception e)
            //{
                //final SecretKey secretKey2 = key2;
            //}
            //SecretKey secretKey2 = (SecretKey) keyStore.getKey(alias, null);
            //stop here
            // Capture the layout's TextView and set the string as its text
            TextView textView = (TextView) findViewById(R.id.textView2);
            //textView.setText(message);
            textView.setText(str);
            final Cipher cipher2 = Cipher.getInstance("AES/GCM/NoPadding");
            final GCMParameterSpec spec = new GCMParameterSpec(128, iv);
            cipher2.init(Cipher.DECRYPT_MODE, secretKey2, spec);
            final byte[] decodedData = cipher2.doFinal(encryption);
            final String unencrypted = new String(decodedData, "UTF-8");
            TextView textView2 = (TextView) findViewById(R.id.textView);
            //textView.setText(message);
            textView2.setText("Decrypted (same instance): "+ unencrypted);
            try (FileOutputStream fos = new FileOutputStream("commstore")) {
                keyStore.store(fos, password);
            }
            catch(Exception e2)
            {
                TextView textView3 = (TextView) findViewById(R.id.textView7);
                //textView.setText(message);
                textView3.setText("Errors: " + e2.getMessage());
            }
        }
        catch (Exception e)
        {
            TextView textView = (TextView) findViewById(R.id.textView);
            //textView.setText(message);
            textView.setText(e.getMessage());
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
    public void sendMessage(View view) {
        Intent intent = new Intent(this, Decrypt.class);
        TextView textView = (TextView) findViewById(R.id.textView2);
        String message = textView.getText().toString();
        TextView textView2 = (TextView) findViewById(R.id.textView4);
        String message2 = textView2.getText().toString();
        //intent.putExtra(, new String [] {message, message2});
        intent.putExtra("IVCT",new String [] {message2,message});
        intent.putExtra("IV",iv_f);
        intent.putExtra("CT",ct_pass);
        startActivity(intent);
    }
}
