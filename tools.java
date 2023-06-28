package com.example.jni222;


import android.util.Log;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSession;





class tools{


    static class NullHostnameVerifier implements HostnameVerifier {
        public boolean verify(String hostname, SSLSession session) {
            return true;
        }
    }

    // weather.visualcrossing.com
    public static DataBeDisplayed parseJsonWeather_0(String result){
        DataBeDisplayed res_obj = new DataBeDisplayed();

                        /*    public String main;

    public String description;
    public double temp;
    public double feels_like;
    public double temp_max;
    public double temp_min;
    public int humidity;
    public int pressure;
    public int visibility;*/

        Log.d("", "current : weather.visualcrossing.com");

        // weather.visualcrossing.com
        result = "{\"queryCost\":1,\"latitude\":42.3221,\"longitude\":-83.1763,\"resolvedAddress\":\"Dearborn, MI, United States\",\"address\":\"Dearborn\",\"timezone\":\"America/Detroit\",\"tzoffset\":-4.0,\"days\":[{\"datetime\":\"2022-05-23\",\"datetimeEpoch\":1653278400,\"tempmax\":16.8,\"tempmin\":10.2,\"temp\":13.2,\"feelslikemax\":16.8,\"feelslikemin\":10.2,\"feelslike\":13.2,\"dew\":3.6,\"humidity\":54.3,\"precip\":0.0,\"precipprob\":0.0,\"precipcover\":0.0,\"preciptype\":null,\"snow\":0.0,\"snowdepth\":0.0,\"windgust\":30.2,\"windspeed\":20.0,\"winddir\":69.7,\"pressure\":1026.4,\"cloudcover\":64.7,\"visibility\":32.0,\"solarradiation\":277.5,\"solarenergy\":24.2,\"uvindex\":10.0,\"severerisk\":10.0,\"sunrise\":\"06:04:14\",\"sunriseEpoch\":1653300254,\"sunset\":\"20:55:19\",\"sunsetEpoch\":1653353719,\"moonphase\":0.79,\"conditions\":\"Partially cloudy\",\"description\":\"Partly cloudy throughout the day.\",\"icon\":\"partly-cloudy-day\",\"stations\":[\"KONZ\",\"F5336\",\"KDET\",\"KDTW\"],\"source\":\"comb\"},{\"datetime\":\"2022-05-24\",\"datetimeEpoch\":1653364800,\"tempmax\":21.6,\"tempmin\":6.3,\"temp\":14.0,\"feelslikemax\":21.6,\"feelslikemin\":3.9,\"feelslike\":13.3,\"dew\":-0.6,\"humidity\":38.1,\"precip\":0.0,\"precipprob\":0.0,\"precipcover\":0.0,\"preciptype\":null,\"snow\":0.0,\"snowdepth\":0.0,\"windgust\":34.9,\"windspeed\":16.6,\"winddir\":45.6,\"pressure\":1023.0,\"cloudcover\":32.9,\"visibility\":51.2,\"solarradiation\":347.8,\"solarenergy\":30.1,\"uvindex\":10.0,\"severerisk\":10.0,\"sunrise\":\"06:03:29\",\"sunriseEpoch\":1653386609,\"sunset\":\"20:56:14\",\"sunsetEpoch\":1653440174,\"moonphase\":0.85,\"conditions\":\"Partially cloudy\",\"description\":\"Partly cloudy throughout the day.\",\"icon\":\"partly-cloudy-day\",\"stations\":null,\"source\":\"fcst\"},{\"datetime\":\"2022-05-25\",\"datetimeEpoch\":1653451200,\"tempmax\":23.4,\"tempmin\":11.1,\"temp\":17.3,\"feelslikemax\":23.4,\"feelslikemin\":11.1,\"feelslike\":17.3,\"dew\":11.0,\"humidity\":68.1,\"precip\":0.0,\"precipprob\":85.7,\"precipcover\":0.0,\"preciptype\":[\"rain\"],\"snow\":0.0,\"snowdepth\":0.0,\"windgust\":51.1,\"windspeed\":20.5,\"winddir\":88.0,\"pressure\":1019.7,\"cloudcover\":89.7,\"visibility\":25.0,\"solarradiation\":266.0,\"solarenergy\":23.0,\"uvindex\":9.0,\"severerisk\":10.0,\"sunrise\":\"06:02:46\",\"sunriseEpoch\":1653472966,\"sunset\":\"20:57:09\",\"sunsetEpoch\":1653526629,\"moonphase\":0.89,\"conditions\":\"Rain, Partially cloudy\",\"description\":\"Partly cloudy throughout the day with a chance of rain.\",\"icon\":\"rain\",\"stations\":null,\"source\":\"fcst\"},{\"datetime\":\"2022-05-26\",\"datetimeEpoch\":1653537600,\"tempmax\":28.3,\"tempmin\":17.9,\"temp\":21.4,\"feelslikemax\":28.4,\"feelslikemin\":17.9,\"feelslike\":21.4,\"dew\":17.4,\"humidity\":80.0,\"precip\":6.3,\"precipprob\":85.7,\"precipcover\":62.5,\"preciptype\":[\"rain\"],\"snow\":0.0,\"snowdepth\":0.0,\"windgust\":51.1,\"windspeed\":26.3,\"winddir\":190.1,\"pressure\":1012.2,\"cloudcover\":93.6,\"visibility\":20.7,\"solarradiation\":222.3,\"solarenergy\":19.3,\"uvindex\":9.0,\"severerisk\":10.0,\"sunrise\":\"06:02:05\",\"sunriseEpoch\":1653559325,\"sunset\":\"20:58:02\",\"sunsetEpoch\":1653613082,\"moonphase\":0.93,\"conditions\":\"Rain, Overcast\",\"description\":\"Cloudy skies throughout the day with a chance of rain throughout the day.\",\"icon\":\"rain\",\"stations\":null,\"source\":\"fcst\"},{\"datetime\":\"2022-05-27\",\"datetimeEpoch\":1653624000,\"tempmax\":22.4,\"tempmin\":16.6,\"temp\":19.4,\"feelslikemax\":22.4,\"feelslikemin\":16.6,\"feelslike\":19.4,\"dew\":16.0,\"humidity\":81.9,\"precip\":11.0,\"precipprob\":52.4,\"precipcover\":75.0,\"preciptype\":[\"rain\"],\"snow\":0.0,\"snowdepth\":0.0,\"windgust\":39.6,\"windspeed\":18.7,\"winddir\":208.8,\"pressure\":1006.0,\"cloudcover\":83.3,\"visibility\":17.2,\"solarradiation\":224.5,\"solarenergy\":19.3,\"uvindex\":8.0,\"severerisk\":10.0,\"sunrise\":\"06:01:26\",\"sunriseEpoch\":1653645686,\"sunset\":\"20:58:54\",\"sunsetEpoch\":1653699534,\"moonphase\":0.96,\"conditions\":\"Rain, Partially cloudy\",\"description\":\"Partly cloudy throughout the day with early morning rain.\",\"icon\":\"rain\",\"stations\":null,\"source\":\"fcst\"},{\"datetime\":\"2022-05-28\",\"datetimeEpoch\":1653710400,\"tempmax\":19.7,\"tempmin\":13.0,\"temp\":16.0,\"feelslikemax\":19.7,\"feelslikemin\":13.0,\"feelslike\":16.0,\"dew\":11.8,\"humidity\":77.8,\"precip\":1.3,\"precipprob\":23.8,\"precipcover\":12.5,\"preciptype\":[\"rain\"],\"snow\":0.0,\"snowdepth\":0.0,\"windgust\":32.0,\"windspeed\":15.8,\"winddir\":192.3,\"pressure\":1009.6,\"cloudcover\":91.3,\"visibility\":22.5,\"solarradiation\":145.5,\"solarenergy\":12.3,\"uvindex\":6.0,\"severerisk\":10.0,\"sunrise\":\"06:00:48\",\"sunriseEpoch\":1653732048,\"sunset\":\"20:59:46\",\"sunsetEpoch\":1653785986,\"moonphase\":0.99,\"conditions\":\"Overcast\",\"description\":\"Cloudy skies throughout the day.\",\"icon\":\"cloudy\",\"stations\":null,\"source\":\"fcst\"},{\"datetime\":\"2022-05-29\",\"datetimeEpoch\":1653796800,\"tempmax\":24.3,\"tempmin\":12.7,\"temp\":18.4,\"feelslikemax\":24.3,\"feelslikemin\":12.7,\"feelslike\":18.4,\"dew\":11.0,\"humidity\":63.8,\"precip\":0.0,\"precipprob\":38.1,\"precipcover\":0.0,\"preciptype\":null,\"snow\":0.0,\"snowdepth\":0.0,\"windgust\":30.2,\"windspeed\":15.5,\"winddir\":141.1,\"pressure\":1013.7,\"cloudcover\":68.1,\"visibility\":24.1,\"solarradiation\":321.8,\"solarenergy\":27.6,\"uvindex\":9.0,\"severerisk\":10.0,\"sunrise\":\"06:00:13\",\"sunriseEpoch\":1653818413,\"sunset\":\"21:00:36\",\"sunsetEpoch\":1653872436,\"moonphase\":1.0,\"conditions\":\"Partially cloudy\",\"description\":\"Partly cloudy throughout the day.\",\"icon\":\"partly-cloudy-day\",\"stations\":null,\"source\":\"fcst\"},{\"datetime\":\"2022-05-30\",\"datetimeEpoch\":1653883200,\"tempmax\":30.4,\"tempmin\":16.7,\"temp\":23.2,\"feelslikemax\":31.4,\"feelslikemin\":16.7,\"feelslike\":23.6,\"dew\":16.3,\"humidity\":66.6,\"precip\":0.0,\"precipprob\":33.3,\"precipcover\":0.0,\"preciptype\":null,\"snow\":0.0,\"snowdepth\":0.0,\"windgust\":45.0,\"windspeed\":25.9,\"winddir\":171.1,\"pressure\":1013.0,\"cloudcover\":75.4,\"visibility\":24.1,\"solarradiation\":296.2,\"solarenergy\":25.8,\"uvindex\":8.0,\"severerisk\":30.0,\"sunrise\":\"05:59:40\",\"sunriseEpoch\":1653904780,\"sunset\":\"21:01:25\",\"sunsetEpoch\":1653958885,\"moonphase\":0.0,\"conditions\":\"Partially cloudy\",\"description\":\"Partly cloudy throughout the day with storms possible.\",\"icon\":\"partly-cloudy-day\",\"stations\":null,\"source\":\"fcst\"},{\"datetime\":\"2022-05-31\",\"datetimeEpoch\":1653969600,\"tempmax\":33.0,\"tempmin\":22.2,\"temp\":27.7,\"feelslikemax\":34.8,\"feelslikemin\":22.2,\"feelslike\":28.7,\"dew\":20.0,\"humidity\":65.5,\"precip\":0.0,\"precipprob\":42.9,\"precipcover\":0.0,\"preciptype\":null,\"snow\":0.0,\"snowdepth\":0.0,\"windgust\":46.1,\"windspeed\":21.6,\"winddir\":226.6,\"pressure\":1014.4,\"cloudcover\":54.4,\"visibility\":24.1,\"solarradiation\":316.4,\"solarenergy\":27.1,\"uvindex\":9.0,\"severerisk\":75.0,\"sunrise\":\"05:59:09\",\"sunriseEpoch\":1653991149,\"sunset\":\"21:02:12\",\"sunsetEpoch\":1654045332,\"moonphase\":0.0,\"conditions\":\"Partially cloudy\",\"description\":\"Partly cloudy throughout the day with strong storms possible.\",\"icon\":\"partly-cloudy-day\",\"stations\":null,\"source\":\"fcst\"},{\"datetime\":\"2022-06-01\",\"datetimeEpoch\":1654056000,\"tempmax\":33.7,\"tempmin\":22.9,\"temp\":28.5,\"feelslikemax\":34.6,\"feelslikemin\":22.9,\"feelslike\":29.2,\"dew\":19.4,\"humidity\":60.2,\"precip\":0.0,\"precipprob\":52.4,\"precipcover\":0.0,\"preciptype\":[\"rain\"],\"snow\":0.0,\"snowdepth\":0.0,\"windgust\":47.2,\"windspeed\":22.3,\"winddir\":232.1,\"pressure\":1013.7,\"cloudcover\":21.9,\"visibility\":24.1,\"solarradiation\":329.3,\"solarenergy\":28.5,\"uvindex\":9.0,\"severerisk\":60.0,\"sunrise\":\"05:58:40\",\"sunriseEpoch\":1654077520,\"sunset\":\"21:02:59\",\"sunsetEpoch\":1654131779,\"moonphase\":0.02,\"conditions\":\"Rain, Partially cloudy\",\"description\":\"Partly cloudy throughout the day with storms possible.\",\"icon\":\"rain\",\"stations\":null,\"source\":\"fcst\"},{\"datetime\":\"2022-06-02\",\"datetimeEpoch\":1654142400,\"tempmax\":26.4,\"tempmin\":13.0,\"temp\":17.5,\"feelslikemax\":26.4,\"feelslikemin\":13.0,\"feelslike\":17.5,\"dew\":10.1,\"humidity\":62.5,\"precip\":0.5,\"precipprob\":52.4,\"precipcover\":16.67,\"preciptype\":[\"rain\"],\"snow\":0.0,\"snowdepth\":0.0,\"windgust\":46.8,\"windspeed\":22.3,\"winddir\":289.7,\"pressure\":1014.6,\"cloudcover\":54.2,\"visibility\":24.0,\"solarradiation\":225.7,\"solarenergy\":19.5,\"uvindex\":7.0,\"severerisk\":30.0,\"sunrise\":\"05:58:12\",\"sunriseEpoch\":1654163892,\"sunset\":\"21:03:44\",\"sunsetEpoch\":1654218224,\"moonphase\":0.04,\"conditions\":\"Rain, Partially cloudy\",\"description\":\"Partly cloudy throughout the day with storms possible.\",\"icon\":\"rain\",\"stations\":null,\"source\":\"fcst\"},{\"datetime\":\"2022-06-03\",\"datetimeEpoch\":1654228800,\"tempmax\":22.8,\"tempmin\":10.3,\"temp\":16.5,\"feelslikemax\":22.8,\"feelslikemin\":10.3,\"feelslike\":16.5,\"dew\":3.5,\"humidity\":45.2,\"precip\":0.0,\"precipprob\":33.3,\"precipcover\":0.0,\"preciptype\":null,\"snow\":0.0,\"snowdepth\":0.0,\"windgust\":25.0,\"windspeed\":14.4,\"winddir\":152.9,\"pressure\":1021.8,\"cloudcover\":22.3,\"visibility\":24.1,\"solarradiation\":355.6,\"solarenergy\":31.1,\"uvindex\":9.0,\"severerisk\":10.0,\"sunrise\":\"05:57:47\",\"sunriseEpoch\":1654250267,\"sunset\":\"21:04:28\",\"sunsetEpoch\":1654304668,\"moonphase\":0.07,\"conditions\":\"Partially cloudy\",\"description\":\"Partly cloudy throughout the day.\",\"icon\":\"partly-cloudy-day\",\"stations\":null,\"source\":\"fcst\"},{\"datetime\":\"2022-06-04\",\"datetimeEpoch\":1654315200,\"tempmax\":25.2,\"tempmin\":13.3,\"temp\":19.4,\"feelslikemax\":25.2,\"feelslikemin\":13.3,\"feelslike\":19.4,\"dew\":7.0,\"humidity\":46.8,\"precip\":0.0,\"precipprob\":47.6,\"precipcover\":0.0,\"preciptype\":[\"rain\"],\"snow\":0.0,\"snowdepth\":0.0,\"windgust\":31.3,\"windspeed\":18.4,\"winddir\":104.4,\"pressure\":1019.9,\"cloudcover\":52.5,\"visibility\":24.1,\"solarradiation\":347.8,\"solarenergy\":30.1,\"uvindex\":9.0,\"severerisk\":10.0,\"sunrise\":\"05:57:24\",\"sunriseEpoch\":1654336644,\"sunset\":\"21:05:10\",\"sunsetEpoch\":1654391110,\"moonphase\":0.11,\"conditions\":\"Rain, Partially cloudy\",\"description\":\"Partly cloudy throughout the day with a chance of rain.\",\"icon\":\"rain\",\"stations\":null,\"source\":\"fcst\"},{\"datetime\":\"2022-06-05\",\"datetimeEpoch\":1654401600,\"tempmax\":28.9,\"tempmin\":16.0,\"temp\":22.8,\"feelslikemax\":28.2,\"feelslikemin\":16.0,\"feelslike\":22.7,\"dew\":12.2,\"humidity\":53.3,\"precip\":0.0,\"precipprob\":33.3,\"precipcover\":0.0,\"preciptype\":null,\"snow\":0.0,\"snowdepth\":0.0,\"windgust\":40.3,\"windspeed\":17.6,\"winddir\":128.4,\"pressure\":1017.3,\"cloudcover\":15.9,\"visibility\":24.1,\"solarradiation\":345.0,\"solarenergy\":30.3,\"uvindex\":9.0,\"severerisk\":10.0,\"sunrise\":\"05:57:03\",\"sunriseEpoch\":1654423023,\"sunset\":\"21:05:51\",\"sunsetEpoch\":1654477551,\"moonphase\":0.14,\"conditions\":\"Clear\",\"description\":\"Clear conditions throughout the day.\",\"icon\":\"clear-day\",\"stations\":null,\"source\":\"fcst\"},{\"datetime\":\"2022-06-06\",\"datetimeEpoch\":1654488000,\"tempmax\":31.2,\"tempmin\":19.8,\"temp\":24.8,\"feelslikemax\":31.6,\"feelslikemin\":19.8,\"feelslike\":24.9,\"dew\":15.5,\"humidity\":57.8,\"precip\":5.6,\"precipprob\":33.3,\"precipcover\":8.33,\"preciptype\":[\"rain\"],\"snow\":0.0,\"snowdepth\":0.0,\"windgust\":39.2,\"windspeed\":20.9,\"winddir\":174.4,\"pressure\":1017.3,\"cloudcover\":27.9,\"visibility\":23.9,\"solarradiation\":299.3,\"solarenergy\":26.1,\"uvindex\":9.0,\"severerisk\":30.0,\"sunrise\":\"05:56:45\",\"sunriseEpoch\":1654509405,\"sunset\":\"21:06:31\",\"sunsetEpoch\":1654563991,\"moonphase\":0.19,\"conditions\":\"Partially cloudy\",\"description\":\"Becoming cloudy in the afternoon with storms possible.\",\"icon\":\"partly-cloudy-day\",\"stations\":null,\"source\":\"fcst\"}],\"stations\":{\"KONZ\":{\"distance\":24761.0,\"latitude\":42.1,\"longitude\":-83.16,\"useCount\":0,\"id\":\"KONZ\",\"name\":\"KONZ\",\"quality\":100,\"contribution\":0.0},\"KDET\":{\"distance\":16853.0,\"latitude\":42.42,\"longitude\":-83.02,\"useCount\":0,\"id\":\"KDET\",\"name\":\"KDET\",\"quality\":100,\"contribution\":0.0},\"F5336\":{\"distance\":8159.0,\"latitude\":42.254,\"longitude\":-83.211,\"useCount\":0,\"id\":\"F5336\",\"name\":\"FW5336 Allen Park MI US\",\"quality\":0,\"contribution\":0.0},\"KDTW\":{\"distance\":16291.0,\"latitude\":42.23,\"longitude\":-83.33,\"useCount\":0,\"id\":\"KDTW\",\"name\":\"KDTW\",\"quality\":100,\"contribution\":0.0}},\"currentConditions\":{\"datetime\":\"09:56:39\",\"datetimeEpoch\":1653314199,\"temp\":12.8,\"feelslike\":12.8,\"humidity\":53.5,\"dew\":3.6,\"precip\":0.0,\"precipprob\":null,\"snow\":0.0,\"snowdepth\":0.0,\"preciptype\":null,\"windgust\":35.3,\"windspeed\":17.4,\"winddir\":45.0,\"pressure\":1029.0,\"visibility\":16.0,\"cloudcover\":93.8,\"solarradiation\":464.0,\"solarenergy\":1.7,\"uvindex\":5.0,\"conditions\":\"Overcast\",\"icon\":\"cloudy\",\"stations\":[\"F5336\",\"KDET\",\"KDTW\"],\"sunrise\":\"06:04:14\",\"sunriseEpoch\":1653300254,\"sunset\":\"20:55:19\",\"sunsetEpoch\":1653353719,\"moonphase\":0.79}}\n";


        try {
            JSONObject obj = new JSONObject(result);

            JSONObject currentObj = obj.getJSONObject("currentConditions");

            res_obj.main = currentObj.getString("conditions");
            res_obj.description = currentObj.getString("conditions");


            res_obj.temp = Double.parseDouble(currentObj.getString("temp"));
            res_obj.feels_like = Double.parseDouble(currentObj.getString("feelslike"));

            res_obj.temp_max = Double.parseDouble(currentObj.getString("temp"));
            res_obj.temp_min = Double.parseDouble(currentObj.getString("temp"));
//
            res_obj.humidity = Double.parseDouble(currentObj.getString("humidity"));
            res_obj.pressure = Double.parseDouble(currentObj.getString("pressure"));


            res_obj.visibility = Double.parseDouble(currentObj.getString("visibility"));

            res_obj.wind_spd = Double.parseDouble(currentObj.getString("windspeed"));


            Log.d("res_obj.main ", res_obj.main);
            Log.d("res_obj.description ", res_obj.description);
            Log.d("res_obj.temp ", String.valueOf(res_obj.temp));
            Log.d("res_obj.feels_like ", String.valueOf(res_obj.feels_like));
            Log.d("res_obj.temp_max ", String.valueOf(res_obj.temp_max));
            Log.d("res_obj.temp_min ", String.valueOf(res_obj.temp_min));
            Log.d("res_obj.humidity ", String.valueOf(res_obj.humidity));
            Log.d("res_obj.pressure ", String.valueOf(res_obj.pressure));
            Log.d("res_obj.visibility ", String.valueOf(res_obj.visibility));
            Log.d("res_obj.wind_spd ", String.valueOf(res_obj.wind_spd));


        } catch (Exception e) {
            e.printStackTrace();
        }







        return res_obj;
    }

    // api.openweathermap.org
    public static DataBeDisplayed parseJsonWeather_2(String result){
        DataBeDisplayed res_obj = new DataBeDisplayed();
                /*    public String main;

    public String description;
    public double temp;
    public double feels_like;
    public double temp_max;
    public double temp_min;
    public int humidity;
    public int pressure;
    public int visibility;*/

        Log.d("", "current : api.openweathermap.org");

        // api.openweathermap.org
        result = "{\"coord\":{\"lon\":-83.1763,\"lat\":42.3223},\"weather\":[{\"id\":803,\"main\":\"Clouds\",\"description\":\"broken clouds\",\"icon\":\"04d\"}],\"base\":\"stations\",\"main\":{\"temp\":300.82,\"feels_like\":303.08,\"temp_min\":298.14,\"temp_max\":303.14,\"pressure\":999,\"humidity\":69},\"visibility\":10000,\"wind\":{\"speed\":11.32,\"deg\":210,\"gust\":13.89},\"clouds\":{\"all\":75},\"dt\":1653071548,\"sys\":{\"type\":2,\"id\":2040983,\"country\":\"US\",\"sunrise\":1653041207,\"sunset\":1653094318},\"timezone\":-14400,\"id\":4990510,\"name\":\"Dearborn\",\"cod\":200}\n";


        try {
            JSONObject obj = new JSONObject(result);

//            JSONObject res = obj.getJSONArray("data").getJSONObject(0);
//            JSONObject wea = obj.getJSONObject("data").getJSONObject("weather");

            JSONObject wea = obj.getJSONArray("weather").getJSONObject(0);

            res_obj.main = wea.getString("main");
            res_obj.description = wea.getString("description");


            JSONObject main = obj.getJSONObject("main");

            res_obj.temp = Double.parseDouble(main.getString("temp"));
            res_obj.feels_like = Double.parseDouble(main.getString("feels_like"));

            res_obj.temp_max = Double.parseDouble(main.getString("temp_max"));
            res_obj.temp_min = Double.parseDouble(main.getString("temp_min"));
//
            res_obj.humidity = Double.parseDouble(main.getString("humidity"));
            res_obj.pressure = Double.parseDouble(main.getString("pressure"));


            res_obj.visibility = Double.parseDouble(obj.getString("visibility"));

            JSONObject wind = obj.getJSONObject("wind");
            res_obj.wind_spd = Double.parseDouble(wind.getString("speed"));


            Log.d("res_obj.main ", res_obj.main);
            Log.d("res_obj.description ", res_obj.description);
            Log.d("res_obj.temp ", String.valueOf(res_obj.temp));
            Log.d("res_obj.feels_like ", String.valueOf(res_obj.feels_like));
            Log.d("res_obj.temp_max ", String.valueOf(res_obj.temp_max));
            Log.d("res_obj.temp_min ", String.valueOf(res_obj.temp_min));
            Log.d("res_obj.humidity ", String.valueOf(res_obj.humidity));
            Log.d("res_obj.pressure ", String.valueOf(res_obj.pressure));
            Log.d("res_obj.visibility ", String.valueOf(res_obj.visibility));
            Log.d("res_obj.wind_spd ", String.valueOf(res_obj.wind_spd));


        } catch (Exception e) {
            e.printStackTrace();
        }



        return res_obj;
    }


    // api.weatherbit.io
    public static DataBeDisplayed parseJsonWeather_1(String result){

        DataBeDisplayed res_obj = new DataBeDisplayed();

        // api.weatherbit.io
        result = "{\"data\":[{\"rh\":72,\"pod\":\"d\",\"lon\":-78.64,\"pres\":1001.8,\"timezone\":\"America\\/New_York\",\"ob_time\":\"2022-05-20 14:00\",\"country_code\":\"US\",\"clouds\":0,\"ts\":1653055200,\"solar_rad\":711.6,\"state_code\":\"NC\",\"city_name\":\"Raleigh\",\"wind_spd\":2.23,\"wind_cdir_full\":\"north-northeast\",\"wind_cdir\":\"NNE\",\"slp\":1013.5,\"vis\":10,\"h_angle\":-38.6,\"sunset\":\"00:17\",\"dni\":857.2,\"dewpt\":22.5,\"snow\":0,\"uv\":5.66793,\"precip\":0,\"wind_dir\":15,\"sunrise\":\"10:04\",\"ghi\":711.61,\"dhi\":108.5,\"aqi\":74,\"lat\":35.78,\"weather\":{\"icon\":\"c01d\",\"code\":800,\"description\":\"Clear sky\"},\"datetime\":\"2022-05-20:14\",\"temp\":28.1,\"station\":\"1327W\",\"elev_angle\":45.36,\"app_temp\":31.1}],\"count\":1}";
        Log.d("", "current : api.weatherbit.io");

        try {
            JSONObject obj = new JSONObject(result);

            JSONObject res = obj.getJSONArray("data").getJSONObject(0);
//            JSONObject wea = obj.getJSONObject("data").getJSONObject("weather");

            JSONObject wea = res.getJSONObject("weather");

            res_obj.main = wea.getString("description");

//            res_obj.city_name = res.getString("city_name");
            res_obj.description = wea.getString("description");
            res_obj.temp = Double.parseDouble(res.getString("temp"));
            res_obj.feels_like = Double.parseDouble(res.getString("app_temp"));
            res_obj.temp_max = Double.parseDouble(res.getString("temp"));
            res_obj.temp_min = Double.parseDouble(res.getString("temp"));

            res_obj.humidity = Double.parseDouble(res.getString("rh"));
            res_obj.pressure = Double.parseDouble(res.getString("slp"));
            res_obj.visibility = Double.parseDouble(res.getString("vis"));

            res_obj.wind_spd = Double.parseDouble(res.getString("wind_spd"));



            Log.d("res_obj.main ", res_obj.main);
//            Log.d("city_name ", res_obj.city_name);
            Log.d("res_obj.description ", res_obj.description);
            Log.d("res_obj.temp ", String.valueOf(res_obj.temp));
            Log.d("res_obj.feels_like ", String.valueOf(res_obj.feels_like));
            Log.d("res_obj.temp_max ", String.valueOf(res_obj.temp_max));
            Log.d("res_obj.temp_min ", String.valueOf(res_obj.temp_min));
            Log.d("res_obj.humidity ", String.valueOf(res_obj.humidity));
            Log.d("res_obj.pressure ", String.valueOf(res_obj.pressure));
            Log.d("res_obj.visibility ", String.valueOf(res_obj.visibility));
            Log.d("res_obj.wind_spd ", String.valueOf(res_obj.wind_spd));



        } catch (Exception e) {
            e.printStackTrace();
        }

        return res_obj;


    }


    public static DataBeDisplayed queryMicroservice(int msId, String msURL) throws Exception{

        System.out.println("*********************************");
        System.out.println("Current running Microservice:");



        System.out.println(msURL);
        Log.d("msURL: ", msURL);

//        msURL = "http://api.weatherstack.com/current?access_key=fd16d137c79bdcd765315117c5c0a930&query=Dearborn";
//        msURL = "https://api.weatherbit.io/v2.0/current?lat=35.7796&lon=-78.6382&key=a7acd8d596344f3f9893042529b25a8f";

		URL url = new URL(msURL);

        // this line of code for the error :
        // when we use ip address to issue https request, there will be a certificate error
        // e.g., "https://207.241.224.2/metadata/TheAdventuresOfTomSawyer_201303";
        HttpsURLConnection.setDefaultHostnameVerifier(new NullHostnameVerifier());

        HttpURLConnection httpURLConnection = (HttpURLConnection) url.openConnection();

        httpURLConnection.setRequestMethod("GET");
//        httpURLConnection.setConnectTimeout(50);

        int responseCode = httpURLConnection.getResponseCode();
        System.out.println("GET Response Code :: " + responseCode);

        if (responseCode == HttpURLConnection.HTTP_OK) { // success
            BufferedReader in = new BufferedReader(new InputStreamReader(httpURLConnection.getInputStream()));
            String inputLine;
            StringBuffer response = new StringBuffer();

            while ((inputLine = in .readLine()) != null) {
                response.append(inputLine);
            } in .close();

            // print result
//            System.out.println(response.toString());
            System.out.println(response);
        } else {
            System.out.println("GET request not worked");
        }

//        for (int i = 1; i <= 8; i++) {
//            System.out.println(httpURLConnection.getHeaderFieldKey(i) + " = " + httpURLConnection.getHeaderField(i));
//        }


        // parsing returned json depending on msId
        DataBeDisplayed res = null;

        if (msId == 0){
            res = parseJsonWeather_0("");

        } else if (msId == 1){
            res = parseJsonWeather_1("");

        } else{
            res = parseJsonWeather_2("");

        }


        res.response_code = HttpURLConnection.HTTP_OK;




//		BufferedReader in = new BufferedReader(new InputStreamReader(con.getInputStream()));
//		String inputLine;
//		StringBuffer content = new StringBuffer();
//		while ((inputLine = in.readLine()) != null) {
//			content.append(inputLine);
//		}
//		in.close();
//		con.disconnect();
//
//		Log.d("query result:", content.toString());

        System.out.println("*********************************");

//        return "success";
        return res;


    }
    /*
     * trim the out most useless parentheses and return a char array
     */
    public static char[] toCharArrayTrimOutParenthes(String src) {

        if (src.length() == 0) {
            return null;
        }
        String result = src;
        while (result.charAt(0) == '(' && result.charAt(result.length() - 1) == ')') {
            if(result.length() == 3) {
                result = result.substring(1, result.length() - 1);
                return result.toCharArray();
                //System.out.println("label"+result);
            }
            int parenthes = 0;
            for (int i = 0; i < result.length() - 1; i++) {
                if (result.charAt(i) == '(') {
                    parenthes++;
                } else if (result.charAt(i) == ')') {
                    parenthes--;
                }
                if (parenthes == 0) {
                    return result.toCharArray();
                }
            }
            result = result.substring(1, result.length() - 1);

        }

        return result.toCharArray();
    }

    public static boolean isOperation(char c) {
        if(c=='-' || c=='*') {
            return true;
        }else {
            return false;
        }
    }

    public static boolean hasOperation(char[] cArray) {
        for (int i = 0; i < cArray.length; i++) {
            if (isOperation(cArray[i])) {
                return true;
            }

        }
        return false;
    }
}