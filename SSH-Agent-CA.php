/*Copyright 2025 Golden-Phy

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.*/
<?php
declare(strict_types=1);
const SSH_AGENT_REQUEST_IDENTITIES = 11;//0x0B
const SSH_AGENT_IDENTITIES_ANSWER = 12;//0x0C
const SSH_AGENT_SIGN_REQUEST = 13;// 0x0D
const SSH_AGENT_SIGN_RESPONSE = 14;// 0x0E
const SUBJECT_FIELD_OID_DICT = [
    "CN" => "\x06\x03\x55\x04\x03", // Common Name (2.5.4.3)
    "O" => "\x06\x03\x55\x04\x0A", // Organization (2.5.4.10)
    "OU" => "\x06\x03\x55\x04\x0B", // Organizational Unit (2.5.4.11)
    "C" => "\x06\x03\x55\x04\x06", // Country (2.5.4.6)
    "ST" => "\x06\x03\x55\x04\x08", // State/Province (2.5.4.8)
    "L" => "\x06\x03\x55\x04\x07", // Locality (2.5.4.7)
];
const SIG_ALGO_DICT = [
    'ssh-ed25519' => ['06032B6570', '06032B6570'],
    'ssh-ed448' => ['06032B6571', '06032B6571'],
    'ecdsa-sha2-nistp256' => ['06072A8648CE3D020106082A8648CE3D030107', '06082A8648CE3D040302'],
    'ecdsa-sha2-nistp384' => ['06072A8648CE3D020106052B81040022', '06082A8648CE3D040303'],
    'ecdsa-sha2-nistp521' => ['06072A8648CE3D020106052B81040023', '06082A8648CE3D040304'],
    'ssh-rsa' => ['06092A864886F70D0101010500', '06092A864886F70D01010B'],
];
$debug = false;
$listKeys = false;
$generateRoot = false;
$keySearchString = '';
$agentSockPath = '';
$hostArg = '';
$caSubjectData = [];
$ptr = null;
foreach ($argv as $item) {
    if (!str_starts_with($item, '-')) {
        $ptr = $item;
        continue;
    }
    $flag = substr($item, 1);
    if (array_key_exists(strtoupper($flag), SUBJECT_FIELD_OID_DICT)) {
        $ptr =& $caSubjectData[strtoupper($flag)];
        continue;
    }
    match ($flag) {
        'r' => $generateRoot = true,
        'k' => $listKeys = true,
        'd' => $debug = true,
        'h' => $ptr =& $hostArg,
        'a' => $ptr =& $agentSockPath,
        's' => $ptr =& $keySearchString,
        default => die("Unknown parameter $flag\n"),
    };
}
if ($listKeys) {
    $socket = agentConnect($agentSockPath);
    readAgentKeys($socket, $keySearchString, print:true);
    die();
} elseif ($hostArg) {
    $names = explode(';', $hostArg);
    $resSTDIN = fopen("php://stdin", "r");
    $hostPublicKey = fgets($resSTDIN);
    $stdinFirstByte = ord($hostPublicKey);
    if ($stdinFirstByte === 0x30) {
        //already DER coded
    } elseif ($stdinFirstByte === ord('-')) {
        //read PEM
        $hostPublicKeyBuffer = '';
        while ($line = fgets($resSTDIN)) {
            if (str_starts_with($line, '----')) break;
            $hostPublicKeyBuffer .= trim($line);
        }
        $hostPublicKey = base64_decode($hostPublicKeyBuffer);
        if ($hostPublicKey === false) die("Invalid PEM, failed to decode public key. Ensure there are no annotations\n");
    } else {
        die("Unsupported public key format, accepts DER and unannotated PEM\n");
    }
} elseif ($generateRoot) {
    //No special action required
} else {
    die("SSH-Agent-CA: Generate and sign X.509 TLS certificates using the SSH agent\n" .
        "Usage: $argv[0] [-o O] [-ou OU] [-d] [-a path] [-s query] {-k | -r | -h CN;SAN[;SAN ...]}
        -cn/o/c... Specify the issuer subject information (Common Name, Organization, etc.)
        -a path    Connect to a specific agent socket instead of relying on the environment
        -s query   Filter available SSH keys by comment to pick a specific SSH CA key from the agent
        -k         List available keys from the SSH agent and exit
        -r         Generate a root CA certificate
        -d         Debug, writes result to cert.der to use with dumpasn1
        -h CN;SAN  Generate a host certificate from a public key
            Pipe or paste the desired server public key into STDIN (SPKI PEM/DER)
    The generated certificate will be provided on STDOUT in PEM format
    To get a chain, issue a root and host certificate with the same issuer subject and SSH CA key
    Note: For verification to work the CA key and issuer information has to match for CA and host certificate
    Tipp: It's not necessary to generate a CA certificate on the host, it only serves for import into a clients truststore\n");
}
$socket = agentConnect($agentSockPath);
$agentKeys = readAgentKeys($socket, $keySearchString);
if (!$agentKeys) die("Found no matching key in the agent at ". getenv("SSH_AUTH_SOCK") . "\n");
$certDer = createCertificate($socket, $agentKeys[0], $caSubjectData, $names ?? [], $hostPublicKey ?? null);
if ($debug) file_put_contents('cert.der', $certDer);
echo "-----BEGIN CERTIFICATE-----\n" . chunk_split(base64_encode($certDer), 64) . "-----END CERTIFICATE-----\n";
die();

function agentConnect(string $sshAgentSock) {
    // Locate the SSH Agent socket
    $sshAgentSock = $sshAgentSock ?: getenv("SSH_AUTH_SOCK");
    if (!$sshAgentSock) die("No SSH agent socket found!\n");
    // Connect to SSH Agent and send the request
    $socket = @stream_socket_client("unix://$sshAgentSock", $errno, $errstr);
    if (!$socket) die("Failed to connect to SSH agent at path $sshAgentSock: $errstr\n");
    return $socket;
}

function readAgentKeys($socket, string $searchRef = '', bool $print = false): array {
    fwrite($socket, str2bin(int2byte(SSH_AGENT_REQUEST_IDENTITIES)));
    $keys = parseAgentSet(readResponse($socket, SSH_AGENT_IDENTITIES_ANSWER));
    $parsedKeys = [];
    while ($keys) {
        $publicKeyBlob = array_shift($keys);
        $comment = array_shift($keys);
        $parsedBlob = parseAgentSet($publicKeyBlob, 0);
        if ($searchRef && false === stripos($comment, $searchRef)) continue;
        $algo = $parsedBlob[0];
        $supported = array_key_exists($algo, SIG_ALGO_DICT);
        if ($print) echo $supported ? "Key available: $algo $comment\n": "\e[2mKey available (unsupported): $algo $comment\e[22m\n";
        if (!$supported) continue;
        $parsedKeys[] = [$comment, $publicKeyBlob, ...$parsedBlob];
    }
    return $parsedKeys;
}

function sign($socket, string $message, string $keyBlob, $sshAlgoName): string {
    $request = //Construct SSH Agent Sign Request
        int2byte(SSH_AGENT_SIGN_REQUEST) . //SSH Agent Message type
        str2bin($keyBlob) . //Public key
        str2bin($message) . //Data to sign
        int2bin($sshAlgoName === 'ssh-rsa' ? 2 : 0); //Flag instructs usage of sha256 for RSA
    fwrite($socket, str2bin($request));
    $data = parseAgentSet(readResponse($socket, SSH_AGENT_SIGN_RESPONSE));
    [$algorithm, $signature] = $data;
    assert($algorithm === $sshAlgoName, 'Key algorithm should not change');
    return $signature;
}

function readResponse($socket, $expectedType): false|string {
    $responseLength = unpack("N", fread($socket, 4))[1];
    $responseType = unpack("C", fread($socket, 1))[1];
    if ($responseType !== $expectedType) die("Error: Unexpected response type $responseType from agent\n");
    $responseBlob = fread($socket, $responseLength - 1);
    assert($responseLength === strlen($responseBlob), 'Unexpected EOF in response from agent');
    return $responseBlob;
}

function parseAgentSet(string $blob, $offset = 4): array {
    $data = [];
    while ($offset < strlen($blob) - 1) {
        $length = unpack("N", substr($blob, $offset, 4))[1];
        $offset += 4;
        $data[] = substr($blob, $offset, $length);
        $offset += $length;
    }
    assert(strlen($blob) === $offset, 'SSH-Agent data-structure must be aligned and complete');
    return $data;
}

function int2byte($value): string {
    return pack("C", $value); // Convert a decimal number into binary (1 byte)
}

function int2bin($value): string {
    return pack("N", $value); // Convert a 32-bit integer into big-endian binary (4 bytes)
}

function str2bin($string): string {
    return int2bin(strlen($string)) . $string;
}

function encodeStringASN1Length(string $string): string {
    $length = strlen($string);
    if ($length < 0x80) return chr($length);
    $bytes = "";
    do {
        $bytes = chr($length & 0xFF) . $bytes;
        $length >>= 8;
    } while ($length > 0);
    return chr(0x80 | strlen($bytes)) . $bytes;
}

function assembleSubject(array $attributes): string {
    $subject = "";
    foreach ($attributes as $type => $value) {
        assert(isset(SUBJECT_FIELD_OID_DICT[$type]));
        $utf8String = "\x0C" . encodeStringASN1Length($value) . $value; // UTF8String
        $entry = SUBJECT_FIELD_OID_DICT[$type] . $utf8String;
        $entrySequence = "\x30" . encodeStringASN1Length($entry) . $entry;
        $entrySet = "\x31" . encodeStringASN1Length($entrySequence) . $entrySequence;
        $subject .= $entrySet;
    }
    return "\x30" . encodeStringASN1Length($subject) . $subject;
}

function assembleSubjectAlternateNames(array $names):string {
    $names = array_map(fn($name) => packSequence($name, "\x82"), $names);
    $sanSequence = packSequence(implode($names));
    $sanOctetString = packSequence($sanSequence, "\x04");
    return  packSequence("\x06\x03\x55\x1D\x11$sanOctetString");
}

function createCertificate($socket, array $agentKey, array $caSubjectData, array $names, ?string $subjectPublicKeyInfo = null): string {
    $caSubjectData['O'] ??= 'Developer SSH key';
    $notBefore = packUTCTime(new DateTime('01/01/2025'));
    $notAfter = packUTCTime(new DateTime('01/01/2045'));

    $caExtensionsTemplate =
        "\x30\x0F\x06\x03\x55\x1D\x13\x01\x01\xFF\x04\x05\x30\x03\x01\x01\xFF" . // Basic Constraints (CA:TRUE)
        "\x30\x0E\x06\x03\x55\x1D\x0F\x01\x01\xFF\x04\x04\x03\x02\x01\x06" . // Key Usage (KeyCertSign, CRLSign)
        "\x30\x19\x06\x03\x55\x1D\x0E\x04\x12\x04\x10%s"; // Subject Key Identifier (Fixed 16 Bytes)
    $hostExtensionsTemplate =
        "\x30\x13\x06\x03\x55\x1D" . /*escape 0x25*/"%\x25\x04\x0C\x30\x0A\x06\x08\x2B\x06\x01\x05\x05\x07\x03\x01" . // serverAuth (TLS)
        "\x30\x0E\x06\x03\x55\x1D\x0F\x01\x01\xFF\x04\x04\x03\x02\x05\xA0" . // KeyUsage (digitalSignature, keyEncipherment)
        "\x30\x1B\x06\x03\x55\x1D\x23\x04\x14\x30\x12\x80\x10%s" . // 16-byte Authority Key Identifier;
        "\x30\x19\x06\x03\x55\x1D\x0E\x04\x12\x04\x10%s"; // 16-byte Subject Key Identifier
    $isHostCert = (bool)$subjectPublicKeyInfo;
    [$publicKeyComment, $publicKeyBlob, $publicKeyAlgo] = $agentKey;
    $issuerPublicKeyBitstring = match ($publicKeyAlgo) {
        'ssh-ed25519', 'ssh-ed448' => $agentKey[3],
        'ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp521' => $agentKey[4],
        'ssh-rsa' => packSequence(sequenceBytes: //PHPStorm format hack
            packSequence($agentKey[4], "\02") . //modulus
            packSequence($agentKey[3], "\02")), //exponent
        default => die("Unsupported algorithm $publicKeyAlgo\n"),
    };
    [$sigAlgoHexKeyOID, $sigAlgoHexSigOID] = SIG_ALGO_DICT[$publicKeyAlgo];
    $sigAlgoSigOID = packSequence(hex2bin($sigAlgoHexSigOID));
    $sigAlgoKeyOID = packSequence(hex2bin($sigAlgoHexKeyOID));
    $issuerPublicKeyInfo = packSequence($sigAlgoKeyOID . packByteAlignedBitstring($issuerPublicKeyBitstring));
    $subjectPublicKeyInfo ??= $issuerPublicKeyInfo;
    $issuerKeyHash = hash('sha256', $issuerPublicKeyInfo, true);
    $subjectKeyHash = hash('sha256', $subjectPublicKeyInfo, true);
    $issuerKeyIdentifier = "\x42" . substr($issuerKeyHash, 0, 15);
    $issuer = assembleSubject($caSubjectData + ['CN' => $publicKeyComment]);
    $issuerIdHash = hash('sha256', "$issuerPublicKeyInfo$issuer", true);
    $issuerSerial = "\x42" . substr($issuerIdHash, 0, 15);
    if ($isHostCert) {
        $subject = assembleSubject(["CN" => $names[0]]);
        $subjectKeyIdentifier = "\x07" . substr($subjectKeyHash, 0, 15);
        $subjectIdHash = hash('sha256', "$subjectPublicKeyInfo$subject", true);
        $subjectSerial = "\x07" . substr($subjectIdHash, 0, 7) . random_bytes(8);
        $extensions = sprintf($hostExtensionsTemplate, $issuerKeyIdentifier, $subjectKeyIdentifier);
        $extensions .= assembleSubjectAlternateNames($names);
        $now = new DateTime();
        $notBefore = packUTCTime($now->sub(new DateInterval('P1D')));
        $notAfter = packUTCTime($now->add(new DateInterval('P91D')));
    } else {
        $subject = $issuer;
        $extensions = sprintf($caExtensionsTemplate, $issuerKeyIdentifier);
        $subjectSerial = $issuerSerial;
    }
    $extensions = packSequence($extensions);
    $extensions = packSequence($extensions, "\xA3");// Explicit Tag denoting extensions
    $validity = packSequence($notBefore . $notAfter);
    $tbsCertificate = packSequence(sequenceBytes: //PHPStorm format hack
        "\xA0\x03" . // Tag
        "\x02\x01\x02" . // Version (v3)
        "\x02\x10$subjectSerial" . // Serial Number
        $sigAlgoSigOID .
        $issuer . $validity . $subject . // Subject same as Issuer when self-signed
        $subjectPublicKeyInfo .
        $extensions);
    $signature = sign($socket, $tbsCertificate, $publicKeyBlob, $publicKeyAlgo);
    if (str_starts_with($publicKeyAlgo, 'ecdsa-')) {//this is leaving the realm of sanity, ECDSA has to be a yoke
        $signatureParts = parseAgentSet($signature, 0);
        $signature = packSequence(sequenceBytes: //PHPStorm format hack
            packSequence($signatureParts[0], "\02") .
            packSequence($signatureParts[1], "\02"));
    }
    $signature = packByteAlignedBitstring($signature);
    return packSequence($tbsCertificate . $sigAlgoSigOID . $signature);
}

function packUTCTime(DateTime $dateTime): string {
    return "\x17\x0D" . $dateTime->format("ymdHis") . "Z";
}

function packSequence(string $sequenceBytes, string $sequenceHeaderByte = "\x30"): string {
    return $sequenceHeaderByte . encodeStringASN1Length($sequenceBytes) . $sequenceBytes;
}

function packByteAlignedBitstring(string $bitstringBytes): string {
    return packSequence("\0$bitstringBytes", "\x03");
}
