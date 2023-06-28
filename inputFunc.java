package com.example.jni222;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.ProtocolException;
import okhttp3.Request;

@FunctionalInterface
public interface inputFunc{
    Request run1(String... args) throws IOException;
//    String run();
}