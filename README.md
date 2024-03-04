![Cryze Logo](docs/CryzeLogo.png)

# Cryze
Cryze is a Wyze Gwell Camera Bridge that allows you to stream your Gwell based Wyze cams to locations of your choosing. Get started below or continue through the readme for more info!

## Installation/Usage
Cryze is composed of two parts: a video proxy in the form of an android application and a server responsible for coordinating the actions of the video proxy. 

### Server
The server is python based and can be installed as follows:
```bash
pip install cryze-server

# Run the server
cryze-server
```

For server options:
```bash
cryze-server -h
```

You can also access a pre-configured version of the server in a docker container:
```bash
cd docker
docker compose up -d cryze-server-service
```

### Proxy
The video proxy is responsible for connecting to your Wyze Gwell based camera and sending those video frames to the cryze-server application. The video proxy waits and listens for specific wyze login info and a device id. Once the proxy has both of those it will connect to your camera and send video frames through the server on a specified websocket channel. The proxy is packaged in a Linux (tested on Ubuntu) Docker container.

To start the docker container:
```bash
cd docker
docker compose up -d cryze-android-service
```

If you want to run the video proxy elsewhere, refer to [Cryze Android](https://github.com/carTloyal123/cryze-android)

## What is Cryze?
Cryze is an open-source project dedicated to providing you access to your own video camera data from Gwell-based Wyze cameras. I believe in giving you control over your camera footage without any restrictions.

Huge shoutout to [mrlt8/docker-wyze-bridge](https://github.com/mrlt8/docker-wyze-bridge) for putting in tremendous work implementing numerous Wyze Cam features and streaming capabilities.

## Contribute
Cryze is an open-source project, and we welcome contributions from the community. Whether you're a developer, designer, or just an enthusiastic user, there are many ways to get involved. Check out our contribution guidelines to see how you can help make Cryze even better.

## Support
If you run into any issues or have questions about using Cryze, don't hesitate to reach out to our community forum. We're here to help!

## License
Cryze is released under the GPLv3 License, which means it's free to use and modify as long as you keep it open source and public, see LISCENSE for more info. We encourage you to customize Cryze to suit your needs.

## Disclaimer
Please note that using Cryze may void your Wyze camera's warranty, and it may not be legal in some regions. Be sure to check your local laws and the terms of service for your Wyze camera before using Cryze.

With that, start enjoying the freedom to access your Wyze camera data with Cryze! 🎉📷