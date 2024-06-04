const fs = require('fs');
const path = require('path');
const https = require("https");
const crypto = require("crypto");
const tmp_path = '/tmp';
const record_line = "默认";
const record_type = "TXT";
const ttl = 3600;
const remark = "LTPP-SSL";

const [cmd_path, run_file_path, SECRET_ID, SECRET_KEY, SLEEP_TIME] = process.argv;
const certbot_domain = process.env.CERTBOT_DOMAIN;
const certbot_validation = process.env.CERTBOT_VALIDATION;
const record_id_file_path = '/tmp/record_id.txt';

function sleep (time) {
    return new Promise((re) => {
        setTimeout(re, time);
    });
}

function deleteFile (file_path = tmp_path) {
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

function writeToFile (file_path = tmp_path, data = '') {
    const absolute_path = path.resolve(file_path);
    if (absolute_path.indexOf(tmp_path) !== 0) {
        return;
    }
    const directory_path = path.dirname(absolute_path);
    try {
        if (!fs.existsSync(directory_path)) {
            fs.mkdirSync(directory_path, { recursive: true });
        }
        fs.writeFileSync(absolute_path, data?.toString() || '');
    } catch (error) {
        console.error('writeToFile error:', error);
    }
}

function getDomain (domain = "") {
    const domain_parts = domain.split('.');
    if (domain_parts.length >= 2) {
        const root_domain = domain_parts.slice(-2).join('.');
        const self_domain = domain_parts.slice(0, -2).join('.');
        return [self_domain, root_domain];
    }
    return ['', domain];
}

function sha256 (message, secret = "", encoding) {
    const hmac = crypto.createHmac("sha256", secret);
    return hmac.update(message).digest(encoding);
}

function getHash (message, encoding = "hex") {
    const hash = crypto.createHash("sha256");
    return hash.update(message).digest(encoding);
}

function getDate (timestamp) {
    const date = new Date(timestamp * 1000);
    const year = date.getUTCFullYear();
    const month = ("0" + (date.getUTCMonth() + 1)).slice(-2);
    const day = ("0" + date.getUTCDate()).slice(-2);
    return `${year}-${month}-${day}`;
}

const domain_list = getDomain(certbot_domain);
const sub_domain = `_acme-challenge${domain_list[0] ? ('.' + domain_list[0]) : domain_list[0]}`;
const domain = domain_list[1];
const host = "dnspod.tencentcloudapi.com";
const service = "dnspod";
const region = "";
const action = "CreateRecord";
const version = "2021-03-23";
const timestamp = parseInt(String(new Date().getTime() / 1000));
const date = getDate(timestamp);

const payload = {
    Domain: domain,
    RecordType: record_type,
    RecordLine: record_line,
    Value: certbot_validation,
    SubDomain: sub_domain,
    TTL: ttl,
    Remark: remark,
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

function add () {
    const req = https.request(options, (res) => {
        let data = "";
        res.on("data", (chunk) => {
            data += chunk;
        });

        res.on("end", () => {
            console.log(data);
            try {
                const record_id = JSON.parse(data)?.Response?.RecordId;
                writeToFile(record_id_file_path, record_id);
            } catch (error) {
                console.error(`add error:${error}`);
            }
        });
    });
    req.on("error", (error) => {
        console.error(`add error:${error}`);
    });
    req.write(payload_json);
    req.end();
}



(async () => {
    deleteFile(record_id_file_path);
    add();
    await sleep(SLEEP_TIME * 1000);
})();