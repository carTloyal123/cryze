import requests
import os
import logging
import subprocess
import time

from enum import Enum

UTF8 = "utf-8"

def get_latest_artifact(owner, repo, save_path) -> str:
    headers = {
        'Accept': 'application/vnd.github.v3+json'
    }
    
    # Get the latest release
    latest_release_url = f"https://api.github.com/repos/{owner}/{repo}/releases/latest"
    response = requests.get(latest_release_url, headers=headers)
    
    if response.status_code != 200:
        raise Exception(f"Failed to fetch the latest release: {response.status_code}, {response.text}")
    
    latest_release = response.json()
    print(f"Latest release: {latest_release['tag_name']}")
    
    # Find the asset
    assets = latest_release['assets']
    if not assets:
        raise Exception("No assets found in the latest release")
    
    # Download the first asset (you can modify this to download a specific asset if needed)
    asset = assets[0]
    download_url = asset['browser_download_url']
    file_name = asset['name']
    
    print(f"Downloading {file_name} from {download_url}")
    download_response = requests.get(download_url, headers=headers)
    
    if download_response.status_code != 200:
        raise Exception(f"Failed to download the asset: {download_response.status_code}, {download_response.text}")
    
    # Save the file
    full_file_path = os.path.join(save_path, file_name)
    with open(full_file_path, 'wb') as file:
        file.write(download_response.content)
    
    print(f"Downloaded {file_name} successfully")
    return file_name

class ReadinessCheck(Enum):
    BOOTED = "booted"
    RUN_STATE = "in running state"
    WELCOME_SCREEN = "in welcome screen"
    POP_UP_WINDOW = "pop up window"

def check_adb_command(readiness_check_type: ReadinessCheck, bash_command: str,
                        expected_keyword: str, max_attempts: int, interval_waiting_time: int,
                        adb_action: str = None) -> None:
    success = False
    for _ in range(1, max_attempts):
        if success:
            break
        else:
            try:
                output = subprocess.check_output(
                    bash_command.split()).decode(UTF8)
                if expected_keyword in str(output).lower():
                    if readiness_check_type is ReadinessCheck.POP_UP_WINDOW:
                        subprocess.check_call(adb_action, shell=True)
                    else:
                        print("Success!")
                        success = True
                else:
                    print(f"Expected keyword '{expected_keyword}' is not found, sleeping...")
                    time.sleep(interval_waiting_time)
            except subprocess.CalledProcessError:
                time.sleep(2)
                continue
    else:
        if readiness_check_type is ReadinessCheck.POP_UP_WINDOW:
            print(f"Pop up windows '{expected_keyword}' is not found!")
        else:
            raise RuntimeError(
                f"{readiness_check_type.value} is checked {_} times!")

def install_app() -> None:
    app_github_repo = "cryze-android"
    app_owner = "carTloyal123"
    save_path = os.getcwd()
    print(f"Downloading the latest release of {app_github_repo} to {save_path}")
    file_name = get_latest_artifact(app_owner, app_github_repo, save_path)
    app_path = os.path.join(save_path, file_name)
    install_cmd = f"adb install -r {app_path}"
    interval_waiting: int = 2
    print(f"Installing app from {app_path}")
    check_adb_command(ReadinessCheck.BOOTED, install_cmd, "success", 60, interval_waiting)
    print(f"App is installed!")
    ## Run App
    run_app_cmd = f"adb shell monkey -p com.tencentcs.iotvideo -v 1"
    print("Running start command!")
    check_adb_command(ReadinessCheck.BOOTED, run_app_cmd, "finished", 60, interval_waiting)
    print(f"App is running!!!!")

def main():
    install_app()


if __name__ == "__main__":
    main()