#!/bin/sh
# URLエンコード関数 (日本語対応)
url_encode() {
    printf "%s" "$1" | jq -sRr @uri
}
# IAM account credentials 

# ヘルプ関数の定義
# ヘルプ関数の定義
show_help() {
  echo "Usage: $0 -t to@example.com -c cc@example.com -b bcc@example.com -m 'body text' -s 'subject'"
  echo ""
  echo "必要な環境変数:"
  echo "  AWS_ACCESS_KEY_ID      AWSアクセスキーID (IAM認証に使用)"
  echo "  AWS_SECRET_ACCESS_KEY  AWSシークレットアクセスキー (IAM認証に使用)"
  echo "  SES_SENDER_EMAIL       SES送信元のメールアドレス"
  echo "  SES_REGION             AWS SESの利用リージョン (例: us-east-1)"
  echo ""
  echo "オプション:"
  echo "  -t  送信先のToアドレス (複数指定可)"
  echo "  -c  送信先のCCアドレス (複数指定可)"
  echo "  -b  送信先のBCCアドレス (複数指定可)"
  echo "  -m  メッセージ本文。'\\\n' を含めると改行として処理されます。"
  echo "  -s  メールの件名"
  echo "  -h  ヘルプの表示"
  echo ""
  echo "依存ツール:"
  echo "  このスクリプトは以下のコマンドが必要です:"
  echo "    jq: URLエンコードに使用。インストールされていない場合、以下のコマンドでインストールしてください:"
  echo "      Linux: sudo apt-get install jq"
  echo "      macOS (Homebrew経由): brew install jq"
  echo "    curl: HTTPリクエストに使用。ほとんどのシステムに標準でインストールされていますが、必要に応じて追加してください。"
  echo "    openssl: 署名の生成に使用。多くのシステムに標準インストールされていますが、必要に応じて追加してください。"
  echo ""
  echo "注意: このスクリプトはmacOSでのみ動作確認済みです。他のOSで使用する場合は依存ツールの確認と適応が必要です。"
}


iamKey="${AWS_ACCESS_KEY_ID}"
iamSecret="${AWS_SECRET_ACCESS_KEY}"
sender_email="${SES_SENDER_EMAIL}"
region="${SES_REGION}"

#region="ap-northeast-3"
service="ses"
host="email.${region}.amazonaws.com"

signedHeaders="host;x-amz-date"

# email parameters

action="SendEmail"


# 変数の初期化
toaddresses=()
ccaddresses=()
bccaddresses=()
message_body=""
message_subject=""

while getopts "t:c:b:m:s:h" opt; do
  case "$opt" in
    t) toaddresses+=("$OPTARG") ;;  # Toアドレスを追加
    c) ccaddresses+=("$OPTARG") ;;  # CCアドレスを追加
    b) bccaddresses+=("$OPTARG") ;; # BCCアドレスを追加
    m) message_body=$(printf "%b" "$OPTARG") ;; # メッセージ本文
    s) message_subject="$OPTARG" ;; # 件名
    h) show_help; exit 0 ;;         # ヘルプの表示
    *) show_help; exit 1 ;;         # 不正なオプション時もヘルプ表示
  esac
done


# URLエンコード済みの変数を使って request_body を作成
encoded_action=$(url_encode "$action")
encoded_sender_email=$(url_encode "$sender_email")
encoded_message_body=$(url_encode "$message_body")
encoded_message_subject=$(url_encode "$message_subject")

# request_body の初期化
request_body="Action=${encoded_action}"


# BCCアドレスを request_body に追加
for i in "${!bccaddresses[@]}"; do
    encoded_address=$(url_encode "${bccaddresses[i]}")
    request_body+="&Destination.BccAddresses.member.$((i+1))=${encoded_address}"
done


# CCアドレスを request_body に追加
for i in "${!ccaddresses[@]}"; do
    encoded_address=$(url_encode "${ccaddresses[i]}")
    request_body+="&Destination.CcAddresses.member.$((i+1))=${encoded_address}"
done

# 宛先 (To) を request_body に追加
for i in "${!toaddresses[@]}"; do
    encoded_address=$(url_encode "${toaddresses[i]}")
    request_body+="&Destination.ToAddresses.member.$((i+1))=${encoded_address}"
done


# 残りのパラメータを request_body に追加
request_body+="&Message.Body.Text.Data=${encoded_message_body}&Message.Subject.Data=${encoded_message_subject}&Source=${encoded_sender_email}"



dateValue1=`TZ=GMT date "+%Y%m%d"`
dateValue2=`TZ=GMT date "+%Y%m%dT%H%M%SZ"`
# Payload is often empty for most GET service requests.
request_payload=""


#------------------------------------
# Step 1 - Create canonical request.
#------------------------------------
#request_payload_sha256=$(echo -n $request_payload | openssl dgst -sha256 | sed 's/^.* //')

request_payload_sha256=$( printf "${request_payload}" | openssl dgst -binary -sha256 | xxd -p -c 256 )

canonical_request=$( printf "%s" "GET
/
${request_body}
host:${host}
x-amz-date:${dateValue2}

${signedHeaders}
${request_payload_sha256}" )

echo "DEBUG: canonical request: ${canonical_request}"exit;
#------------------------------------
# Step 2 - Create string to sign.
#------------------------------------
#canonical_request_sha256=$(echo -n "${canonical_request}" | openssl dgst -sha256 | sed 's/^.* //')


canonical_request_sha256=$( printf "%s" "${canonical_request}" | openssl dgst -binary -sha256 | xxd -p -c 256 )
stringToSign=$( printf "AWS4-HMAC-SHA256
${dateValue2}
${dateValue1}/${region}/${service}/aws4_request
${canonical_request_sha256}" )
# echo "DEBUG: stringToSign: ${stringToSign}"


stringToSign="AWS4-HMAC-SHA256\n${dateValue2}\n${dateValue1}/${region}/${service}/aws4_request\n${canonical_request_sha256}"
#echo "DEBUG: stringToSign: ${stringToSign}"; exit;

#------------------------------------
# Step 3 - Calculate signature.
#------------------------------------
kSecret=$(   printf "AWS4${iamSecret}" | xxd -p -c 256 )
kDate=$(     printf "${dateValue1}"    | openssl dgst -binary -sha256 -mac HMAC -macopt hexkey:${kSecret}       | xxd -p -c 256 )
kRegion=$(   printf "${region}"        | openssl dgst -binary -sha256 -mac HMAC -macopt hexkey:${kDate}         | xxd -p -c 256 )
kService=$(  printf "${service}"       | openssl dgst -binary -sha256 -mac HMAC -macopt hexkey:${kRegion}       | xxd -p -c 256 )
kSigning=$(  printf "aws4_request"     | openssl dgst -binary -sha256 -mac HMAC -macopt hexkey:${kService}      | xxd -p -c 256 )
signature=$( printf "${stringToSign}"  | openssl dgst -binary -hex -sha256 -mac HMAC -macopt hexkey:${kSigning} | sed 's/^.* //' )
# echo "DEBUG: signature: ${signature}"

#------------------------------------
# Step 4 - Add signature to request.
#------------------------------------


curl --request GET --silent \
     -H "Authorization: AWS4-HMAC-SHA256 Credential=${iamKey}/${dateValue1}/${region}/${service}/aws4_request, SignedHeaders=${signedHeaders}, Signature=${signature}" \
     -H "Content-type: application/x-www-form-urlencoded;" \
     -H "Host: ${host}" \
     -H "X-Amz-Date: ${dateValue2}" \
     "https://${host}/?${request_body}"

exit $?
