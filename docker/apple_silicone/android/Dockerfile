FROM --platform=$BUILDPLATFORM eclipse-temurin:latest


RUN apt-get update && apt-get install -y \
    python3-pip repo wget python-is-python3 unzip curl jq libpcre2-dev adb \
    && rm -rf /var/lib/apt/lists/*

RUN wget https://dl.google.com/android/repository/commandlinetools-linux-11076708_latest.zip -O /tmp/android-sdk.zip

RUN unzip /tmp/android-sdk.zip -d /opt/android-sdk

RUN mkdir -p /tmp/latest-tools && mv /opt/android-sdk/cmdline-tools/* /tmp/latest-tools
RUN mkdir -p /opt/android-sdk/cmdline-tools/latest && mv /tmp/latest-tools/* /opt/android-sdk/cmdline-tools/latest

ENV ANDROID_SDK_ROOT=/opt/android-sdk
ENV ANDROID_HOME=/opt/android-sdk
ENV ANDROID_EMULATOR_WAIT_TIME_BEFORE_KILL=60

ENV PATH=$PATH:/opt/android-sdk/cmdline-tools/latest/bin

RUN yes | sdkmanager --update
RUN yes | sdkmanager --licenses

COPY emulator/ /opt/android-sdk/emulator/
COPY package.xml /opt/android-sdk/emulator/package.xml

# RUN sdkmanager "system-images;android-34;google_apis;arm64-v8a" 
RUN sdkmanager "system-images;android-34;aosp_atd;arm64-v8a" 

ARG EMULATOR_NAME="nexus"
ARG EMULATOR_DEVICE="Nexus 10"
ENV EMULATOR_NAME=$EMULATOR_NAME
ENV DEVICE_NAME=$EMULATOR_DEVICE
RUN echo "no" | avdmanager --verbose create avd --force --name "${EMULATOR_NAME}" --device "${EMULATOR_DEVICE}" --package "system-images;android-34;aosp_atd;arm64-v8a"

RUN mkdir /opt/android-sdk/platforms && mkdir /opt/android-sdk/platform-tools 
RUN echo "Vulkan = off" >> ~/.android/advancedFeatures.ini && echo "GLDirectMem = on" >> ~/.android/advancedFeatures.ini

# Download the latest release APK URL from GitHub API
ENV GITHUB_REPO="carTloyal123/cryze-android"
# Download the APK file
RUN wget -q $(curl -s "https://api.github.com/repos/$GITHUB_REPO/releases/latest" | jq -r '.assets[0].browser_download_url') -O app.apk

COPY ./run_emu.sh .
RUN chmod a+x run_emu.sh

CMD ["tail", "-f", "/dev/null"]