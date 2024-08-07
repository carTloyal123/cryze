#!/bin/bash
BL='\033[0;34m'
G='\033[0;32m'
RED='\033[0;31m'
YE='\033[1;33m'
NC='\033[0m' # No Color

emulator_name=${EMULATOR_NAME}

function check_hardware_acceleration() {
    if [[ "$HW_ACCEL_OVERRIDE" != "" ]]; then
        hw_accel_flag="$HW_ACCEL_OVERRIDE"
    else
        if [[ "$OSTYPE" == "darwin"* ]]; then
            # macOS-specific hardware acceleration check
            HW_ACCEL_SUPPORT=$(sysctl -a | grep -E -c '(vmx|svm)')
        else
            # generic Linux hardware acceleration check
            HW_ACCEL_SUPPORT=$(grep -E -c '(vmx|svm)' /proc/cpuinfo)
        fi

        if [[ $HW_ACCEL_SUPPORT == 0 ]]; then
            hw_accel_flag="-accel off"
        else
            hw_accel_flag="-accel on"
        fi
    fi

    echo "$hw_accel_flag"
}


hw_accel_flag=$(check_hardware_acceleration)

function launch_emulator () {
  adb devices | grep emulator | cut -f1 | xargs -I {} adb -s "{}" emu kill

  # specific to mac apple silicon for some reason
  nohup /opt/android-sdk/emulator/emulator @nexus -no-window -no-audio -ports 5554,5555 -skip-adb-auth -no-boot-anim -show-kernel -qemu -cpu max &

  if [ $? -ne 0 ]; then
    echo "Error launching emulator"
    return 1
  fi
}

function check_emulator_status () {
  printf "${G}==> ${BL}Checking emulator booting up status 🧐${NC}\n"
  start_time=$(date +%s)
  spinner=( "⠹" "⠺" "⠼" "⠶" "⠦" "⠧" "⠇" "⠏" )
  i=0
  # Get the timeout value from the environment variable or use the default value of 300 seconds (5 minutes)
  timeout=${EMULATOR_TIMEOUT:-300}

  while true; do
    result=$(adb shell getprop sys.boot_completed 2>&1)

    if [ "$result" == "1" ]; then
      printf "\e[K${G}==> \u2713 Emulator is ready : '$result'           ${NC}\n"
      adb devices -l
      adb shell input keyevent 82
      break
    elif [ "$result" == "" ]; then
      printf "${YE}==> Emulator is partially Booted! 😕 ${spinner[$i]} ${NC}\r"
    else
      printf "${RED}==> $result, please wait ${spinner[$i]} ${NC}\r"
      i=$(( (i+1) % 8 ))
    fi

    current_time=$(date +%s)
    elapsed_time=$((current_time - start_time))
    if [ $elapsed_time -gt $timeout ]; then
      printf "${RED}==> Timeout after ${timeout} seconds elapsed 🕛.. ${NC}\n"
      break
    fi
    sleep 4
  done
};

launch_emulator
sleep 1
check_emulator_status
sleep 1

# Set up environment variables
export ANDROID_HOME=/opt/android
export PATH=$PATH:$ANDROID_HOME/tools:$ANDROID_HOME/platform-tools

# Wait for the emulator to start
adb wait-for-device

# # Install the APK on the emulator
adb install -r app.apk

echo "Running Application!"
# Run the installed APK
adb shell monkey -p com.tencentcs.iotvideo -v 1
echo "APK installed and running"
tail -f /dev/null

# # Start the emulator
# echo "Launch emulator in background"
# nohup /opt/android-sdk/emulator/emulator @nexus -no-window -no-audio -ports 5554,5555 -skip-adb-auth -no-boot-anim -show-kernel -qemu -cpu max &

# # Wait for the emulator to start
# adb wait-for-device

# # Install app
# adb install -r app.apk

# # Launch app
# adb shell monkey -p com.tencentcs.iotvideo -v 1
# echo "APK installed and running"
# tail -f /dev/null
