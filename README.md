# Service-Polymorphism

Service Polymorphism: Serving Clients Dissimilarly to Enhance Web Service Performance for Mobile Apps.

# Requirement
- Android 10 Mobile Phone with normal CPU and Memory configuration. Root permission is not required.
- WiFi Router that supports to flash OpenWRT
	- our implemenation is based on OpenWRT 21.02, but it is supposed to run on other versions
- A Ubuntu 18.04 desktop PC as a resolver (Optional)

# Usage Example
 
        TranslationService ws = new TranslationService(this.getApplicationContext()); // create a Polymorphic Service
        ws.Input("Hello, World", "es"); // assign the Polymorphic Services invoke parameters
        ws.init("Lat_Opt"); // initiate the Polymorphic Services

        ws.exec(); // invoke Polymorphic Services 

        String[] trans_info = ws.GetRes(); // fetch the result

		// display the result
        for (String item: trans_info){
            Log.d("translation", item);
        }
        ws.ReportQoS(); // report service QoS to the forwarder
