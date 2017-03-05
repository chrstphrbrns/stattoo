//
//  DetachedSignature.swift
//  stattoo
//
//  Created by Christopher Burns on 8/19/16.
//  Copyright © 2016 Christopher Burns. All rights reserved.
//

import Foundation
import Security
import Crypto
import Net

var httpCache:[URL:([AnyHashable:Any],Data)] = [:]
func getHttp(url:URL, for file:SignedFile) -> ([AnyHashable:Any],Data)? {
    if let result = httpCache[url] {
        return result
    }
    
    if let result = HttpGet(url: url), result.headers["x-amz-meta-hmac"] != nil {
        if CommandLineOptions.force == false {
            info_func(file: file, message: "found cloud signature")
        }

        httpCache[url] = result
    }
    
    return httpCache[url]
}

struct DetachedSignature {
	let signedhash:SignedData
	let certificate:SecCertificate?
	let timestamp:Data?
	var cloudTimestamp:Date?
	
	init(signedhash:SignedData, certificate:SecCertificate? = nil, timestamp:Data? = nil, cloudTimestamp:Date? = nil) {
		self.signedhash = signedhash
		self.certificate = certificate
		self.timestamp = timestamp
		self.cloudTimestamp = cloudTimestamp
	}
	
	init?(filename:String) {
		if let text = try? String(contentsOfFile: filename) {
			self.init(text: text)
		} else {
			return nil
		}
	}
	
	private init?(text:String, cloudTimestamp:Date? = nil) {
		let datas = text.extractPemBlobs()
		
		if datas.count == 0 {
			return nil
		}
		
		var signedhash:SignedData!
		if let sig = SignedData.from(json: datas[0].0) {
			signedhash = sig
		} else {
			return nil
		}
		
		var certificate:SecCertificate? = nil
		var timestamp:Data? = nil
		for i in 1..<datas.count {
			if datas[i].1 == "CERTIFICATE" {
				certificate = SecCertificateCreateWithData(nil, datas[i].0 as CFData)
			} else if datas[i].1 == "SECURE TIMESTAMP" {
				timestamp = datas[i].0
			} else {
				return nil
			}
		}
		
		self.signedhash = signedhash
		self.certificate = certificate
		self.timestamp = timestamp
		self.cloudTimestamp = cloudTimestamp
	}

	private func makeContents() -> String {
		var s = ""
		
		s.append(signedhash.toJSON().pem(withIdentifier: "STATTOO SIGNED HASH") + "\n")
		
		if let certificate = certificate {
			s.append(certificate.data().pem(withIdentifier: "CERTIFICATE") + "\n")
		}
		
		if let timestamp = timestamp {
			s.append(timestamp.pem(withIdentifier: "SECURE TIMESTAMP") + "\n")
		}

		return s
	}
	
	func write(filename:String) throws -> Bool {
		let s = makeContents()
		
		try s.write(toFile: filename, atomically: true, encoding: .utf8)
		
		return stattoo.writeExtendedAttribtue(Data(), named: COM_CHRIS_XATTR_KEY_IS_SIGNATURE, to: filename)
	}

    let a = 1
    
    // TODO: the AWS HMAC is basically redundant
    // TODO: encryptionKey should be a Key instead of SecKey (so it can be a SymmetricHardwareKey
	func write(url:URL, encryptionKey:SecKey, hmacKey:Data) throws -> String? {
		var s = makeContents()
		
		s = s
			.data(using: .utf8)!
			.encrypt(withKey: encryptionKey)
			.encode(withKey: hmacKey)
			.pem(withIdentifier: "STATTOO ENCRYPTED SIGNATURE")
		
#if DEBUG_LOCAL_CLOUD
		try s.write(toFile: url.absoluteString, atomically: true, encoding: .utf8)
		return url.absoluteString
#else
		if let bucket = url.host {
			let path = url.path.trim(charactersInString: "/")
			if let aws_key_id = ProcessInfo().environment["AWS_KEY_ID"], let aws_key_value = ProcessInfo().environment["AWS_KEY_VALUE"] {
				let aws_key = AwsKey(id: aws_key_id, value: aws_key_value, hmacKey: hmacKey)
				let bucket = AwsBucket(name: bucket, key: aws_key)
                let headers = ["keytype":keyid!.0, "keyid":keyid!.1, "signed": self.certificate != nil ? "yes" : "no"]
                return bucket.put(object: .text(s), forKey: path, withOptions: [.Public, .Encrypted], headers: headers)
			} else {
				error_func(message: "AWS environment variables not set")
			}
		}
#endif
		
		return nil
	}
	
    enum CloudResult {
        case headers([AnyHashable:Any])
        case signature(DetachedSignature)
    }
    
	// TODO: modify to get the original version of the given key, so the timestamp is meaningful
    static func getFromCloud(for file:SignedFile, headersOnly:Bool = false) throws -> CloudResult? {
		// TODO: this will return nil if the sig exists, but we're using the wrong key
		// key ID header on the AWS put operation should solve

#if DEBUG_LOCAL_CLOUD
        return getFromLocalCloud(for: file)
#endif
        
		guard let url = file.cloudURL else {
			return nil
		}

        if let (headers, pem) = getHttp(url: url, for: file) {
            if headersOnly {
                return .headers(headers)
            }
            
			guard let hmac = headers["x-amz-meta-hmac"] as! String? else {
				return nil
			}

            if let keytype = headers["x-amz-meta-keytype"] as? String, let keyid = headers["x-amz-meta-keyid"] as? String {
                file.keyType = keytype
                file.keyID = keyid
                file.setKey(withKeyType: keytype, keyID: keyid)
            }
            
            guard let encryptionKey = file.encryptionKey else {
                return nil
            }

            guard let hmacKey = file.hmacKey else {
                return nil
            }

			let df = DateFormatter()
			// eg, Tue, 06 Sep 2016 00:16:49 GMT
			df.dateFormat = "EEE, dd MMM yyyy HH:mm:ss zzz"
			
			guard let lastModified = headers["Last-Modified"] as! String? else {
				return nil
			}
			
			if let cloudTimestamp = df.date(from: lastModified) {
				if let aws_key_id = ProcessInfo().environment["AWS_KEY_ID"], let aws_key_value = ProcessInfo().environment["AWS_KEY_VALUE"] {
					let aws_key = AwsKey(id: aws_key_id, value: aws_key_value, hmacKey: hmacKey)
					if pem.secureHash(withKey: aws_key.hmacKey, algorithm: .sha256).secureEquals(Data.fromHex(hmac)!) {
						if let data = extractPemPayloadData(pem) {
							if let encrytedData = EncryptedData.decode(data, withKey: hmacKey) {
								if let plain = encrytedData.decrypt(withKey: encryptionKey) {
									if let str = plain.string(using: .utf8) {
                                        if let sig = DetachedSignature(text: str, cloudTimestamp: cloudTimestamp) {
                                            file.keyType = sig.signedhash.unsignedAttributes?["keytype"] as? String ?? ""
                                            file.keyID = sig.signedhash.unsignedAttributes?["keyid"] as? String ?? ""
                                            file.certificate = sig.certificate
                                            file.setKey(withKeyType: file.keyType!, keyID: file.keyID!)
                                            return .signature(sig)
                                        } else {
                                            return nil
                                        }
									}
								}
							}
						}
					} else {
						error_func(file: file, message: "invalid signature")
					}
				} else {
					error_func(file: file, message: "AWS environment variables not set")
				}
			}
			
			throw NSError(domain: "stattoo", code: 3, userInfo: nil)
		}
		
		return nil
	}
    
    static func getFromLocalCloud(for file:SignedFile) -> DetachedSignature? {
        guard let encryptionKey = file.encryptionKey else {
            fatal_func(message: "no hardware key available")
        }
        
        guard let hmacKey = file.hmacKey else {
            fatal_func(message: "no hardware key available")
        }
        
        if let url = file.cloudURL?.absoluteString {
            if let pem = try? Data(contentsOf: URL(fileURLWithPath: url)) {
                if let data = extractPemPayloadData(pem) {
                    if let encrytedData = EncryptedData.decode(data, withKey: hmacKey) {
                        if let plain = encrytedData.decrypt(withKey: encryptionKey) {
                            if let str = plain.string(using: .utf8) {
                                if let timestamp = try? FileManager.default.attributesOfItem(atPath: url)[FileAttributeKey.modificationDate]! as? Date {
                                    return DetachedSignature(text: str, cloudTimestamp: timestamp)
                                }
                            }
                        }
                    }
                }
            }
        }
        
        return nil
    }
}
