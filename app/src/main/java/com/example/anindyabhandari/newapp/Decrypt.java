package com.example.anindyabhandari.newapp;

import android.content.Intent;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.widget.TextView;

import java.io.FileInputStream;
import java.security.KeyStore;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

public class Decrypt extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_decrypt);
        Intent intent = getIntent();
        String [] stuff = intent.getStringArrayExtra("IVCT");
        //String iv = stuff[0];
        byte[] iv=intent.getByteArrayExtra("IV");
        //String ct = stuff[1];//intent.getStringExtra("ciphertext");
        byte[] ct=intent.getByteArrayExtra("CT");
        TextView textView0 = (TextView) findViewById(R.id.textView5);
        //textView.setText(message);
        textView0.setText("IV is: "+iv);
        TextView textView1 = (TextView) findViewById(R.id.textView6);
        //textView.setText(message);
        textView1.setText("Ciphertext: "+ct);
        //adding this part, feel free to change
        String alias = "Hello";
        try {
            //final KeyGenerator keyGenerator = KeyGenerator
            //.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");//ANDROID_KEY_STORE);

            //final KeyGenParameterSpec keyGenParameterSpec = new KeyGenParameterSpec.Builder(alias,
            //KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
            //.setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            //.setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            //.build();

            //keyGenerator.init(keyGenParameterSpec);
            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");//KeyStore.getDefaultType());
            keyStore.load(null);
            //char[] password = {'p', 'a', 's', 's'};
            //try (FileInputStream fis = new FileInputStream("keyStoreName")) {
            //keyStore.load(fis, password);
            //}
            //try (FileInputStream fis = new FileInputStream("commstore")) {
                //keyStore.load(fis, password);
            //}
            //KeyStore.ProtectionParameter pp = new KeyStore.PasswordProtection(password);
            final KeyStore.SecretKeyEntry secretKeyEntry = (KeyStore.SecretKeyEntry) keyStore.getEntry(alias, null);//pp);
            final SecretKey secretKey2 = secretKeyEntry.getSecretKey();
            //stop here
            // Capture the layout's TextView and set the string as its text
            final Cipher cipher2 = Cipher.getInstance("AES/GCM/NoPadding");
            final GCMParameterSpec spec = new GCMParameterSpec(128, iv);//.getBytes());
            cipher2.init(Cipher.DECRYPT_MODE, secretKey2, spec);
            final byte[] decodedData = cipher2.doFinal(ct);//.getBytes());
            final String unencrypted = new String(decodedData, "UTF-8");
            TextView textView2 = (TextView) findViewById(R.id.textView3);
            //textView.setText(message);
            textView2.setText(unencrypted);
        }
        catch (Exception e) {
            TextView textView = (TextView) findViewById(R.id.textView3);
            //textView.setText(message);
            textView.setText("Errors: "+e.getMessage());
            return;
        }
    }
}
