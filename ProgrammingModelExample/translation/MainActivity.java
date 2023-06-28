package com.example.translation;

import androidx.appcompat.app.AppCompatActivity;

import android.os.Bundle;
import android.util.Log;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.concurrent.ExecutionException;

public class MainActivity extends AppCompatActivity {


    public void invokeTranslationWS() throws IOException, ExecutionException, InterruptedException, NoSuchAlgorithmException {

       
        TranslationService ws = new TranslationService(this.getApplicationContext());
        ws.Input("Hello, World", "zh-CN", "en");
        ws.init("Lat_Opt");

        ws.exec();

        String[] trans_info = ws.GetRes();

//         display weather_info on UI
        for (String item: trans_info){
            Log.d("myapp3", item);
        }
//
        ws.ReportQoS();


        Log.d("", "*********************************************************");
    }


    

    

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);


        try {
            invokeTranslationWS();
        } catch (IOException | ExecutionException | InterruptedException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }



    }
}