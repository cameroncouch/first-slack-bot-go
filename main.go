package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
)

func slackDefault(w http.ResponseWriter, r *http.Request) {
	// fmt.Println("Endpoint Hit: slackDefault")

	type slackChallenge struct {
		Challenge string `json:"challenge"`
	}

	if r.Body == nil {
		http.Error(w, "Please send a request body", 400)
		return
	}

	b, _ := io.ReadAll((*r).Body)
	//what does this do
	defer (*r).Body.Close()
	//Build Slack's required verification string from v0:ts:body
	var ts string = r.Header.Get("X-Slack-Request-Timestamp")
	//sha256 hash encrypt the string to prepare for comparison
	var verif string = generateVerificationHash("v0:" + ts + ":" + string(b))

	//compare
	// fmt.Println(verif)
	// fmt.Println(r.Header.Get("X-Slack-Signature"))
	if hmac.Equal([]byte(verif), []byte(r.Header.Get("X-Slack-Signature"))) {
		//write the response
		w.Header().Add("Content-type", "application/json")
		w.WriteHeader(200)

		var jsonBody map[string]interface{}
		var challenge slackChallenge

		//take request data and unmarshal it into interface and struct
		json.Unmarshal(b, &challenge)
		json.Unmarshal(b, &jsonBody)

		if event, ok := jsonBody["event"].(map[string]interface{}); ok {
			// fmt.Println(event["type"])
			reply := sendReply(&event)

			responseBody := bytes.NewBuffer(reply)

			req, err := http.NewRequest("POST", "https://slack.com/api/chat.postMessage", responseBody)

			req.Header.Set("Authorization", os.Getenv("slackGoBearer"))
			req.Header.Set("Content-Type", "application/json")

			resp, err := http.DefaultClient.Do(req)

			if err != nil {
				log.Fatalf("An error occurred %v", err)
			}

			defer resp.Body.Close()

		} else if challenge.Challenge != "" {
			// fmt.Printf("Challenge: %s", challenge.Challenge)
			marshalChallenge, _ := json.Marshal(challenge)
			w.Write([]byte(marshalChallenge))
		} else {
			fmt.Println("Expected to respond to a Slack Challenge or to a Slack Event")
		}
	} else {
		w.Header().Add("Content-type", "application/json")
		w.WriteHeader(400)
		w.Write([]byte(`{"error": "Verification failed The verification string does not match the X-Slack-Signature"}`))
	}
}

func generateVerificationHash(vString string) string {
	//Store as ENV var
	var secret string = os.Getenv("slackGoSecret")
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(vString))
	sha := hex.EncodeToString(h.Sum(nil))
	return "v0=" + sha
}

func sendReply(message *map[string]interface{}) []byte {
	type Reply struct {
		Channel string `json:"channel"`
		Text    string `json:"text"`
	}

	marshalReply, _ := json.Marshal(Reply{Channel: (*message)["channel"].(string), Text: (*message)["text"].(string)})

	return marshalReply
}

func handleRequests() {
	http.HandleFunc("/", slackDefault)
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func main() {
	handleRequests()
}
