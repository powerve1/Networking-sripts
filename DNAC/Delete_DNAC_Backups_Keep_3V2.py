import urllib3
import requests
import json
import getpass
import datetime
import os

#Gets all available backups from DNAC, keeps the THREE newest, and deletes the rest. REST delete call is ENABLED (live deletion).
#Loops so you can process multiple Catalyst Centers in one run, reusing the same credentials but prompting for each new IP.

#Disable "InsecureRequestWarning: Unverified HTTPS request is being made."
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

#Build a log file path anchored next to this script, so it works regardless of the current working directory
script_dir = os.path.dirname(os.path.abspath(__file__))
log_dir = os.path.join(script_dir, 'files')
os.makedirs(log_dir, exist_ok=True)  #Create the 'files' subfolder if it does not exist
log_path = os.path.join(log_dir, 'DNAC_backups_cleanup_log.txt')


def process_catalyst_center(DNAC_IP, username, password, file):
    #Processes a single Catalyst Center: authenticate, list backups, confirm, and delete all but the 3 newest.

    #DNAC Login request
    url1 = "https://" + DNAC_IP + "/dna/system/api/v1/auth/token"
    payload = ""
    token = requests.request("POST", url1, auth=(username, password), data=payload, verify=False)
    token = token.text.replace('{"Token":"', '')  #Converts token to str and removes string at the begining of response token
    token = token.replace('"}', '')  #Removes string at the end of response token

    #Get available backups
    url2 = "https://" + DNAC_IP + "/api/system/v1/maglev/backup"
    payload={}
    headers = {
      'Content-Type': 'application/json',
      'x-auth-token': token
    }

    #REST call
    get_available_backups= requests.request("GET", url2, headers=headers, data=payload, verify=False)

    #Convert response to JSON
    get_available_backups_json = json.loads(get_available_backups.text)

    #Parses JSON and generates two lists: one with just the time_stamps (UNIX Epoch) and another list (tuple) with time_stams and job_id
    time_stamps_list = []
    time_id_tuple =[]
    time_id_tuple_list = []

    counter_2 = 0
    for val_1 in get_available_backups_json["response"]:
        #Condition to only use jobs with success status
        if get_available_backups_json["response"][counter_2]["status"] == "SUCCESS":
            time_stamps_list.append(get_available_backups_json["response"][counter_2]["end_timestamp"])
            time_id_tuple = (get_available_backups_json["response"][counter_2]["end_timestamp"], get_available_backups_json["response"][counter_2]["backup_id"])
            time_id_tuple_list.append(time_id_tuple)
            counter_2 += 1

    #Determine indexes of the THREE newest timestamps (keep_indexes), without mutating the original list permanently
    working_time_stamps = time_stamps_list.copy()
    keep_indexes = []

    num_to_keep = min(3, len(working_time_stamps))

    for _ in range(num_to_keep):
        newest_index = working_time_stamps.index(max(working_time_stamps))
        keep_indexes.append(newest_index)
        working_time_stamps[newest_index] = float('-inf')

    #Build preview lists (keep vs delete), sorted newest-first for readability
    keep_preview = []
    delete_preview = []

    for x in range(0, counter_2):
        end_time = get_available_backups_json["response"][x]["backup_services"][0]["end_time"]
        backup_id = get_available_backups_json["response"][x]["backup_id"]
        end_timestamp = get_available_backups_json["response"][x]["end_timestamp"]
        if x in keep_indexes:
            keep_preview.append((end_timestamp, end_time, backup_id))
        else:
            delete_preview.append((end_timestamp, end_time, backup_id))

    #Sort both newest-first by epoch timestamp
    keep_preview.sort(key=lambda item: item[0], reverse=True)
    delete_preview.sort(key=lambda item: item[0], reverse=True)

    #Display the THREE backups that will be KEPT
    print("")
    print("=== Catalyst Center " + DNAC_IP + " ===")
    print("=== KEEPING the 3 newest backups ===")
    for end_timestamp, end_time, backup_id in keep_preview:
        print("KEEP   " + str(end_time) + "   ID: " + str(backup_id))

    #Display all backups that will be DELETED
    print("")
    print("=== DELETING " + str(len(delete_preview)) + " backup(s) ===")
    for end_timestamp, end_time, backup_id in delete_preview:
        print("DELETE " + str(end_time) + "   ID: " + str(backup_id))

    #Confirmation prompt before any deletion occurs
    print("")
    confirm = input("Proceed with deleting the " + str(len(delete_preview)) + " backup(s) listed above? (Y/N): ")

    if confirm.strip().upper() != "Y":
        print("Aborted by user. No backups were deleted on " + DNAC_IP + ".")
        file.write('----------------' + str(datetime.datetime.now()) + '----------------')
        file.write('\n')
        file.write("Catalyst Center " + DNAC_IP + ": run aborted by user at confirmation prompt. No backups deleted.")
        file.write('\n')
        file.write('\n')
        return

    #Write log file header for this center
    file.write('----------------' + str(datetime.datetime.now()) + '----------------')
    file.write('\n')
    file.write("Catalyst Center " + DNAC_IP)

    #Condition to confirm that there are more than three backups before attempting any deletion
    if len(time_stamps_list) > 3:
      deleted_count = 0
      failed_count = 0
      failed_ids = []

      for x in range (0, counter_2):
          #Condition to delete jobs with list indexes not in the keep_indexes (newest three)
          if x not in keep_indexes:
            #Delete backups by ID
            url2 = "https://" + DNAC_IP + "/api/system/v1/maglev/backup/" + get_available_backups_json["response"][x]["backup_id"]
            payload={}
            headers = {
             'Content-Type': 'application/json',
             'x-auth-token': token
            }

            #REST call to delete the backup (LIVE)
            del_available_backups= requests.request("DELETE", url2, headers=headers, data=payload, verify=False)

            #Condition to check if REST call was successful
            if int(del_available_backups.status_code) >= 200 and int(del_available_backups.status_code) < 300:
              deleted_count += 1
              print("DELETED " + str(get_available_backups_json["response"][x]["backup_services"][0]["end_time"]) + "   ID: " + str(get_available_backups_json["response"][x]["backup_id"]))
              file.write('\n')
              file.write("Backup succesfully removed:")
              file.write('\n')
              file.write("Job ID " + str(get_available_backups_json["response"][x]["backup_id"]))
              file.write('\n')
              file.write("Job end time " + str(get_available_backups_json["response"][x]["backup_services"][0]["end_time"]))
              file.write('\n')
              file.write('\n')

            else:
              failed_count += 1
              failed_ids.append(get_available_backups_json["response"][x]["backup_id"])
              print("FAILED  " + str(get_available_backups_json["response"][x]["backup_services"][0]["end_time"]) + "   ID: " + str(get_available_backups_json["response"][x]["backup_id"]) + "   (status " + str(del_available_backups.status_code) + ")")
              file.write('\n')
              file.write("Backup removal failed:")
              file.write('\n')
              file.write("Job ID " + str(get_available_backups_json["response"][x]["backup_id"]))
              file.write('\n')
              file.write("Job end time " + str(get_available_backups_json["response"][x]["backup_services"][0]["end_time"]))
              file.write('\n')
              file.write("Status code " + str(del_available_backups.status_code))
              file.write('\n')
              file.write('\n')

      #End-of-run summary (console + log)
      print("")
      print("=== Deletion complete for " + DNAC_IP + " ===")
      print("Requested for deletion: " + str(len(delete_preview)))
      print("Successfully deleted:   " + str(deleted_count))
      print("Failed:                 " + str(failed_count))
      if failed_count > 0:
          print("Failed backup IDs: " + str(failed_ids))
      if deleted_count == len(delete_preview):
          print("All targeted backups were deleted. 3 newest backups retained.")
      else:
          print("WARNING: not all targeted backups were deleted. Review the failed IDs above and the log file.")

      file.write('\n')
      file.write("Summary: requested " + str(len(delete_preview)) + ", deleted " + str(deleted_count) + ", failed " + str(failed_count))
      file.write('\n')
      if failed_count > 0:
          file.write("Failed backup IDs: " + str(failed_ids))
          file.write('\n')
      file.write('\n')

    else:
      print("Catalyst Center " + DNAC_IP + " contains three backups or less, none deleted.")
      file.write('\n')
      file.write("Catalyst Center contains three backups or less, none deleted")
      file.write('\n')
      file.write('\n')


#=== Main ===

#Collect credentials ONCE; they are reused for every Catalyst Center processed this run
username = input('Catalyst Center User: ')
password = getpass.getpass('Catalyst Center Password: ')

#Open log file once and keep it open across all centers
file = open(log_path, 'a')

try:
    while True:
        DNAC_IP = input('DNAC IP: ')
        process_catalyst_center(DNAC_IP, username, password, file)

        #Ask whether to process another Catalyst Center using the same credentials
        another = input("Process another Catalyst Center with the same credentials? (Y/N): ")
        if another.strip().upper() != "Y":
            print("Done. Exiting.")
            break
finally:
    file.close()