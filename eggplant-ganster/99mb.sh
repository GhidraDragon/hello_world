ffmpeg -y -i "$1" -c:v libx264 -b:v 1254k -pass 1 -an -f mp4 /dev/null && \
ffmpeg -i "$1" -c:v libx264 -b:v 1254k -pass 2 -c:a aac -b:a 128k output2.mp4