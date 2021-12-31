require requests
require fio
require daslib/strings_boost

[export]
def main
    var finished = false

    var onResponse <- @ <| (resp:Response)
        print("Response received: status code = {resp.code}\n")
        print("Body length: {length(resp.body)}\n")
        print("Body: {resp.body[0]}, {resp.body[1]}...\n")
        print("Body text: {resp.text |> slice(0, 200)}\n")
        finished = true


    var onProgress <- @ <| (total:uint; current:uint)
        print("Progress: {current} / {total}\n")


    let params <- [[RequestParams
        method = "GET",
        url = "http://localhost:8000/",
        callback <- onResponse,
        onProgress <- onProgress
    ]]

    print("Sending request...\n")
    request(params)

    print("Request sent, polling\n")
    for i in range(0, 3)
        sleep(100u)
        requests_poll()
        if finished
            break

    print("Done\n")
