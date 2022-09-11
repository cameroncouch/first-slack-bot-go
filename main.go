package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
)

func slackDefault(w http.ResponseWriter, r *http.Request) {
	fmt.Println("Endpoint Hit: slackDefault")

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
	var ts string = r.Header.Get("X-Slack-Request-Timestamp");
	//sha256 hash encrypt the string to prepare for comparison
	var verif string = generateVerificationHash("v0:"+ts+":"+string(b));
	
	//compare
	fmt.Println(verif)
	fmt.Println(r.Header.Get("X-Slack-Signature"))
	if hmac.Equal([]byte(verif), []byte (r.Header.Get("X-Slack-Signature"))) {
		//write the response
		w.Header().Add("Content-type","application/json")
		w.WriteHeader(200)
		
		var jsonBody map[string]interface {}
		var challenge slackChallenge

		json.Unmarshal([]byte(b), &jsonBody)
		json.Unmarshal([]byte(b), &challenge)

		if event, ok := jsonBody["event"].(map[string]interface{}); ok {
			fmt.Println(event["type"]);
		} else if challenge.Challenge != "" {
			fmt.Printf("Challenge: %s", challenge.Challenge)
			w.Write([]byte(challenge.Challenge))
		} else {
			fmt.Println("No key 'event' exists in the request body")
		}
	} else {
		w.Header().Add("Content-type","application/json")
		w.WriteHeader(400)
		jsonData := map[string]string {"error":"Verification failed The verification string does not match the X-Slack-Signature"}
		jsonValue, _ := json.Marshal(jsonData)
		w.Write([]byte(jsonValue))
	}
}

func generateVerificationHash(vString string) string {
	//Store as ENV var
	var secret string = "null"
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(vString))
	sha := hex.EncodeToString(h.Sum(nil))
	return "v0=" + sha;
}

func handleRequests() {
	http.HandleFunc("/", slackDefault)
	//http.HandleFunc("/math", mathRoute)
	//http.HandleFunc("/string", stringRoute)
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func main() {
	handleRequests()
}