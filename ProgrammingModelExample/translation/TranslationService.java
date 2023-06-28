package com.example.translation;

import android.content.Context;

import com.example.jni222.EqvService;
import com.example.jni222.PolymorphicWebService;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;

import okhttp3.FormBody;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;

public class TranslationService extends PolymorphicWebService {

    public String text;
    public String to_lang;
    public String from_lang;


    public TranslationService(Context context) {
        super(context);
    }

    public void init(String... arg) throws IOException{

        EqvService Eq1 = new EqvService("NLPTranslation", "fff0cce889msh638a3ec1dd45f71p1d8592jsn6253d876837c", 67);
        EqvService Eq2 = new EqvService("TextTranslator", "fff0cce889msh638a3ec1dd45f71p1d8592jsn6253d876837c", 50);
        EqvService Eq3 = new EqvService("LectoTranslation", "fff0cce889msh638a3ec1dd45f71p1d8592jsn6253d876837c", 67);

        Eq1.connectInput(args -> {

            Request request = new Request.Builder()
//                    .url("https://nlp-translation.p.rapidapi.com/v1/translate?text=Hello%2C%20world!!&to=es&from=en")
                    .url("https://nlp-translation.p.rapidapi.com/v1/translate?text=" + args[0] + "&to=" + args[1] + "&from=" + args[2])
                    .get()
                    .addHeader("X-RapidAPI-Key", "700ff85788msh2173763d8b71da6p1a9874jsn74387dfb61f0")
                    .addHeader("X-RapidAPI-Host", "nlp-translation.p.rapidapi.com")
                    .build();


            return request;
        }, this.text, this.to_lang, this.from_lang);


        Eq2.connectInput(args -> {

            RequestBody body = new FormBody.Builder()
                    .add("source_language", args[2])
                    .add("target_language", args[1])
                    .add("text", args[0])
                    .build();

            Request request = new Request.Builder()
                    .url("https://text-translator2.p.rapidapi.com/translate")
                    .post(body)
                    .addHeader("content-type", "application/x-www-form-urlencoded")
                    .addHeader("X-RapidAPI-Key", "700ff85788msh2173763d8b71da6p1a9874jsn74387dfb61f0")
                    .addHeader("X-RapidAPI-Host", "text-translator2.p.rapidapi.com")
                    .build();


            return request;

        }, this.text, this.to_lang, this.from_lang);


        Eq3.connectInput(args -> {

            MediaType mediaType = MediaType.parse("application/json");
//            String value1 = "{\n    \"texts\": [\n        \"Hello World\"\n    ],\n    \"to\": [\n        \"hi\"\n    ],\n    \"from\": \"en\"\n}";
            String value = "{\n    \"texts\": [\n         \"" +  args[0] + "\" \n ], \n  \"to\": [\n        \"" + args[1] + "\" \n  ], \n  \"from\": \"" + args[2] + "\" \n}";

            RequestBody body = RequestBody.create(mediaType, value);
            Request request = new Request.Builder()
                    .url("https://lecto-translation.p.rapidapi.com/v1/translate/text")
                    .post(body)
                    .addHeader("content-type", "application/json")
                    .addHeader("X-RapidAPI-Key", "700ff85788msh2173763d8b71da6p1a9874jsn74387dfb61f0")
                    .addHeader("X-RapidAPI-Host", "lecto-translation.p.rapidapi.com")
                    .build();

            return request;

        }, this.text, this.to_lang, this.from_lang);


        this.addEqvService(Eq1, Eq2, Eq3);

        if (arg.length == 2)
            this.setPattern(arg[0], arg[1]);
        else
            this.setPattern(arg[0]);

        this.setDefaultStrategy("0");


        Eq1.connectOutput((resp) -> {
            String[] OI = new String[1];
            try {
                JSONObject obj = new JSONObject(resp);
                JSONObject translated = obj.getJSONObject("translated_text");
                String translated_text = translated.getString("zh-CN");
                OI[0] = translated_text;

            } catch (JSONException e) {
                e.printStackTrace();
            }


            return OI;
        });

        Eq2.connectOutput((resp)->{
            String[] OI = new String[1];
            try {
                JSONObject obj = new JSONObject(resp);
                JSONObject data = obj.getJSONObject("data");
                String translatedText = data.getString("translatedText");
                OI[0] = translatedText;

            } catch (JSONException e) {
                e.printStackTrace();
            }


            return OI;
        });



        Eq3.connectOutput((resp)->{

            String[] OI = new String[1];
            try {
                JSONObject obj = new JSONObject(resp);
                JSONObject translations = obj.getJSONArray("translations").getJSONObject(0);
                String translated = translations.getString("translated");
                OI[0] = translated;

            } catch (JSONException e) {
                e.printStackTrace();
            }


            return OI;

        });

    }


    public void Input (String... args){
        this.text = args[0];
        this.to_lang = args[1];
        this.from_lang = args[2];
    }


}
