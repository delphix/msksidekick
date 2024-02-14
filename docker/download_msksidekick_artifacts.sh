#!/bin/bash

# GitHub repo address
REPO="delphix/msksidekick"

# GitHub API token with repo access
GITHUB_TOKEN="$GITHUB_API_TOKEN"

# Function to convert UTC to CST
convert_to_cst() {
    echo "$(TZ='America/Chicago' date -d "$1" '+%Y-%m-%dT%H:%M:%SZ')"
}

# Get the latest run status
latest_run=$(curl -s -H "Authorization: token $GITHUB_TOKEN" \
    "https://api.github.com/repos/$REPO/actions/runs?status=completed&per_page=1")

# Extract relevant information
latest_run_number=$(echo "$latest_run" | jq -r '.workflow_runs[0].run_number')
latest_run_name=$(echo "$latest_run" | jq -r '.workflow_runs[0].name')
latest_run_created_at=$(echo "$latest_run" | jq -r '.workflow_runs[0].created_at')
latest_run_conclusion=$(echo "$latest_run" | jq -r '.workflow_runs[0].conclusion')
latest_run_head_branch=$(echo "$latest_run" | jq -r '.workflow_runs[0].head_branch')
latest_run_display_title=$(echo "$latest_run" | jq -r '.workflow_runs[0].display_title')

# # Convert UTC to CST
# echo "latest_run_created_at: $latest_run_created_at"
# latest_run_created_at_cst=$(convert_to_cst "$latest_run_created_at")
# echo "latest_run_created_at: $latest_run_created_at"

# Check if the latest run was successful
if [[ "$latest_run_conclusion" == "success" ]]; then
    # Get the latest run ID
    latest_run_id=$(echo "$latest_run" | jq -r '.workflow_runs[0].id')

    # Get artifacts for the latest run
    artifacts=$(curl -s -H "Authorization: token $GITHUB_TOKEN" \
        "https://api.github.com/repos/$REPO/actions/runs/$latest_run_id/artifacts")

    # Prompt for output location
    read -p "Enter the output location to save downloaded files: " output_location
    mkdir -p $output_location

    # Check if artifacts are present
    if [ "$(echo "$artifacts" | jq -r '.artifacts | length')" != "null" ] && [ "$(echo "$artifacts" | jq -r '.artifacts | length')" -gt 0 ]; then
        # Iterate over artifacts and download
        echo "$artifacts" | jq -r '.artifacts[] | .name, .archive_download_url' | while read -r name && read -r url; do
            wget --header="Authorization: token $GITHUB_TOKEN" -O "${output_location}/${name}.zip" "$url"
        done
        echo "Artifacts from the latest successful run downloaded successfully."
    else
        echo "No artifacts found in the latest successful run."
    fi
    echo " "
    echo "Latest run was not successful. No artifacts to download."
    echo "Latest Run Number       : $latest_run_number"
    echo "Latest Run Name         : $latest_run_name"
    echo "Latest Run Created At   : $latest_run_created_at"
    echo "Latest Run Conclusion   : $latest_run_conclusion"
    echo "Latest Run Head Branch  : $latest_run_head_branch"
    echo "Latest Run Display Title: $latest_run_display_title"
    echo "Output Location         : $output_location"
    ls -ltr $output_location

    cd $output_location
    unzip linux7build.zip
    rm linux7build.zip

    unzip linux8build.zip
    rm linux8build.zip

    unzip osxbuild.zip
    rm osxbuild.zip

    unzip ubuntu18build.zip
    rm ubuntu18build.zip

    unzip windowsbuild.zip
    rm windowsbuild.zip

else
    echo " "
    echo "Latest run was not successful. No artifacts to download."
    echo "Latest Run Number       : $latest_run_number"
    echo "Latest Run Name         : $latest_run_name"
    echo "Latest Run Created At   : $latest_run_created_at"
    echo "Latest Run Conclusion   : $latest_run_conclusion"
    echo "Latest Run Head Branch  : $latest_run_head_branch"
    echo "Latest Run Display Title: $latest_run_display_title"
    echo "Output Location         : $output_location"
fi
