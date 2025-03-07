

docker run --name smb-test --rm --network bridge -p 445:445 --cap-add NET_ADMIN  \
    -e  \
    smb-tests

# Shows logs in background and 