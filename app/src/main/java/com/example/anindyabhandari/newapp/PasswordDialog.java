package com.example.anindyabhandari.newapp;

import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.text.method.PasswordTransformationMethod;
import android.util.Log;
import android.view.View;
import android.widget.CheckBox;
import android.widget.CompoundButton;
import android.widget.EditText;

public class PasswordDialog extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_password_dialog);
        /*
        final EditText passwordEditView = (EditText) findViewById(R.id.editText2);
        final CheckBox showPasswordCheckBox = (CheckBox) findViewById(R.id.checkbox);
        showPasswordCheckBox.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                if (showPasswordCheckBox.isChecked()){
                    passwordEditView.setTransformationMethod(null);
                }else{
                    passwordEditView.setTransformationMethod(new PasswordTransformationMethod());
                }
            }
        });*/
    }
    public void onCheckedChanged(View view) {//CompoundButton buttonView, boolean isChecked) {
        int start,end;
        boolean isChecked = ((CheckBox) view).isChecked();
        //Log.i("inside checkbox chnge",""+isChecked);
        final EditText passWordEditText = (EditText) findViewById(R.id.editText2);
        if(!isChecked){
            start=passWordEditText.getSelectionStart();
            end=passWordEditText.getSelectionEnd();
            passWordEditText.setTransformationMethod(new PasswordTransformationMethod());;
            passWordEditText.setSelection(start,end);
        }else{
            start=passWordEditText.getSelectionStart();
            end=passWordEditText.getSelectionEnd();
            passWordEditText.setTransformationMethod(null);
            passWordEditText.setSelection(start,end);
        }
    }
}

