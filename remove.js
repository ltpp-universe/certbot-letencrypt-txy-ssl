const fs = require('fs');
const path = require('path');
const https = require("https");
const crypto = require("crypto");
const tmp_path = '/tmp';
const [cmd_path, run_file_path, SECRET_ID, SECRET_KEY] = process.argv;
const certbot_domain = process.env.CERTBOT_DOMAIN;
const record_id_file_path = '/tmp/record_id.txt';

function deleteFile(file_path = tmp_path) {
    try {
        const absolute_path = path.resolve(file_path);
        if (absolute_path.indexOf(tmp_path) !== 0) {
            return;
        }
        if (fs.existsSync(absolute_path)) {
            const stats = fs.statSync(absolute_path);
            if (stats.isFile()) {
                fs.unlinkSync(absolute_path);
            } else if (stats.isDirectory()) {
                fs.rmSync(absolute_path, { recursive: true, force: true });
            }
        }
    } catch (error) {
        console.error('deleteFile error:', error);
    }
}

function readFile(file_path = tmp_path) {
    try {
        const absolute_path = path.resolve(file_path);
        if (absolute_path.indexOf(tmp_path) !== 0) {
            return;
        }
        const data = fs.readFileSync(absolute_path, 'utf8');
        return data;
    } catch (error) {
        console.error(`readFile error:${error}`);
    }
    return '';
}

function getDomain(domain = "") {
    const domain_parts = domain.split('.');
    if (domain_parts.length >= 2) {
        const root_domain = domain_parts.slice(-2).join('.');
        const self_domain = domain_parts.slice(0, -2).join('.');
        return [self_domain, root_domain];
    }
    return ['', domain];
}

function sha256(message, secret = "", encoding) {
    const hmac = crypto.createHmac("sha256", secret);
    return hmac.update(message).digest(encoding);
}

function getHash(message, encoding = "hex") {
    const hash = crypto.createHash("sha256");
    return hash.update(message).digest(encoding);
}

function getDate(timestamp) {
    const date = new Date(timestamp * 1000);
    const year = date.getUTCFullYear();
    const month = ("0" + (date.getUTCMonth() + 1)).slice(-2);
    const day = ("0" + date.getUTCDate()).slice(-2);
    return `${year}-${month}-${day}`;
}

function getNumber(str = "") {
    let res = 0;
    try {
        res = parseInt(str);
    } catch (error) {
        console.error(`getNumber error:${error}`);
    }
    return res;
}

const domain_list = getDomain(certbot_domain);
const sub_domain = domain_list[1];
const host = "dnspod.tencentcloudapi.com";
const service = "dnspod";
const region = "";
const action = "DeleteRecord";
const version = "2021-03-23";
const timestamp = parseInt(String(new Date().getTime() / 1000));
const date = getDate(timestamp);
const record_id = getNumber(readFile(record_id_file_path));

const payload = {
    Domain: sub_domain,
    RecordId: record_id
};

const payload_json = JSON.stringify(payload);

// ************* 步骤 1：拼接规范请求串 *************
const signedHeaders = "content-type;host";
const hashedRequestPayload = getHash(payload_json);
const httpRequestMethod = "POST";
const canonicalUri = "/";
const canonicalQueryString = "";
const canonicalHeaders = "content-type:application/json; charset=utf-8\n" + "host:" + host + "\n";

const canonicalRequest =
    httpRequestMethod +
    "\n" +
    canonicalUri +
    "\n" +
    canonicalQueryString +
    "\n" +
    canonicalHeaders +
    "\n" +
    signedHeaders +
    "\n" +
    hashedRequestPayload;

// ************* 步骤 2：拼接待签名字符串 *************
const algorithm = "TC3-HMAC-SHA256";
const hashedCanonicalRequest = getHash(canonicalRequest);
const credentialScope = date + "/" + service + "/" + "tc3_request";
const stringToSign =
    algorithm +
    "\n" +
    timestamp +
    "\n" +
    credentialScope +
    "\n" +
    hashedCanonicalRequest;

// ************* 步骤 3：计算签名 *************
const kDate = sha256(date, "TC3" + SECRET_KEY);
const kService = sha256(service, kDate);
const kSigning = sha256("tc3_request", kService);
const signature = sha256(stringToSign, kSigning, "hex");

// ************* 步骤 4：拼接 Authorization *************
const authorization =
    algorithm +
    " " +
    "Credential=" +
    SECRET_ID +
    "/" +
    credentialScope +
    ", " +
    "SignedHeaders=" +
    signedHeaders +
    ", " +
    "Signature=" +
    signature;

// ************* 步骤 5：构造并发起请求 *************
const headers = {
    Authorization: authorization,
    "Content-Type": "application/json; charset=utf-8",
    Host: host,
    "X-TC-Action": action,
    "X-TC-Timestamp": timestamp,
    "X-TC-Version": version,
};

if (region) {
    headers["X-TC-Region"] = region;
}

const options = {
    hostname: host,
    method: httpRequestMethod,
    headers,
};

function remove() {
    const req = https.request(options, (res) => {
        let data = "";
        res.on("data", (chunk) => {
            data += chunk;
        });

        res.on("end", () => {
            console.log(data);
        });
    });
    req.on("error", (error) => {
        console.error(`remove error:${error}`);
    });
    req.write(payload_json);
    req.end();
}

deleteFile(record_id_file_path);
remove();