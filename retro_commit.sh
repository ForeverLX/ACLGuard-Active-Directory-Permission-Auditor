#!/bin/bash
# retro_commit.sh – create fake commit history

# Replace this with the GitHub-linked email
export GIT_AUTHOR_NAME="Darrius Grate"
export GIT_AUTHOR_EMAIL="darriusthegrate2@gmail.com"
export GIT_COMMITTER_NAME="Darrius Grate"
export GIT_COMMITTER_EMAIL="darriusthegrate2@gmail.com"

# Start date
start_date="2025-08-03"

# Number of days of work to simulate
days=7

# Array of commit messages
messages=(
  "Initial commit: Project setup"
  "Implement config loading"
  "Add LDAP connection handling"
  "Create permission checking module"
  "Add CSV export functionality"
  "Implement error handling"
  "Refactor codebase for clarity"
  "Final polish before public release"
)

for i in $(seq 0 $days); do
  commit_date=$(date -d "$start_date +$i days" +"%Y-%m-%dT14:00:00")
  
  # Make a small change to ensure commit is unique
  echo "Progress log for day $i" > "progress_$i.txt"
  
  git add .
  GIT_COMMITTER_DATE="$commit_date" \
  GIT_AUTHOR_DATE="$commit_date" \
  git commit -m "${messages[$i]}"
done

for day in "${days[@]}"; do
    commit_date=$(date -d "$start_date + $day days" +"%Y-%m-%d %H:%M:%S")
    export GIT_AUTHOR_DATE="$commit_date"
    export GIT_COMMITTER_DATE="$commit_date"

    echo "Update project files on $commit_date" > "progress_$day.txt"
    git add .
    git commit -m "Work on day $day – progress update"
done

echo "Retro commits complete. You can now push to GitHub."

