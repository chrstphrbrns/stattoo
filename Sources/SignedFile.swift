//
//  SignedFile.swift
//  stattoo
//
//  Created by Christopher Burns on 8/19/16.
//  Copyright © 2016 Christopher Burns. All rights reserved.
//

import Foundation
import Crypto

extension Data {
	func toBase64StringX() -> String {
		return self.base64EncodedString()
			// https://tools.ietf.org/html/rfc3986#section-2.3
			//  "Characters that are allowed in a URI but do not have a reserved
			//   purpose are called unreserved.  These include uppercase and lowercase
			//   letters, decimal digits, hyphen, period, underscore, and tilde."
			.replacingOccurrences(of: "/", with: "-")
			.replacingOccurrences(of: "+", with: ".")
			.replacingOccurrences(of: "=", with: "_")
	}

	// ~5.94 bits of entropy per character since "a" and "b" are more probable
	func toBase64StringY() -> String {
		return self.base64EncodedString()
			.replacingOccurrences(of: "/", with: "a")
			.replacingOccurrences(of: "+", with: "b")
			.replacingOccurrences(of: "=", with: "")
	}
}

func readExtendedAttribute(named name:String, from filename:String) -> Data? {
	let size = getxattr(filename, name, nil, 0, 0, 0)
	if size >= 0 {
		let buffer = UnsafeMutablePointer<Int8>.allocate(capacity: size)
		if getxattr(filename, name, buffer, size, 0, 0) == -1 {
			return nil
		} else {
			return Data(bytes: buffer, count: size)
		}
	}
	
	return nil
}

func writeExtendedAttribtue(_ data:Data, named name:String, to filename:String) -> Bool {
	if setxattr(filename, name, data.unsafeBytePointer, data.count, 0, 0) != 0 {
		return false
	}
	
	return true
}

func deleteExtendedAttribtue(named name:String, from filename:String) -> Bool {
	if removexattr(filename, name, 0) != 0 {
		return false
	}
	
	return true
}

class SignedFile {
	let filename:String
	
	init(filename:String) {
		self.filename = filename
	}

	lazy var isDetachedSignatureFile : Bool = {
		return FileManager.default.extendedAttributeNamesOfItem(atPath: self.filename).contains("stattoo.is_signature")
	}()

	// true if the file was properly signed with a private key (and thus has an x509 cert attached);
	// false if the file was merely tagged (MAC'd)
	lazy var isSigned : Bool = {
		if self.cloudOnly {
			if let temp = try? DetachedSignature.getFromCloud(for: self, headersOnly: true), case .headers(let headers) = temp ?? .headers([:]) {
				return (headers["x-amz-meta-signed"] as? String) ?? "" == "yes"
			}
			
			return false
		} else {
			return self.certificate != nil
		}
	}()
	
	var exists : Bool {
		return FileManager.default.fileExists(atPath: filename)
	}
	
	lazy var isDirectory : Bool = {
		var isDirectory : ObjCBool = false
		return FileManager.default.fileExists(atPath: self.filename, isDirectory: &isDirectory) && isDirectory.boolValue
	}()
	
	var pastTenseVerb : String {
		return isSigned ? "signed" : "tagged"
	}

	func setKey(withKeyType keyType:String, keyID:String) {
		let _ = retrieve_key(params: ["keytype":keyType,"keyid":keyID])
	}

	private static var _cache:[String:Key] = [:]
	func retrieve_key(params:[String:Any]) -> Key? {
		guard let type = params["keytype"] as? String else {
			return nil
		}
		
		guard let id = params["keyid"] as? String else {
			return nil
		}

		let salt = params["salt"]
		var saltData:Data? = nil
		if let salt = salt as? String {
			saltData = Data.fromHex(salt)
			if saltData == nil {
				fatal_func(message: "password signature missing salt")
			}
		}
		
		if let key = SignedFile._cache[id] {
			return key
		}
		
		switch type {
		case "air":
			_airKey?.disconnect()
			info_func(file: self, message: "verify with \("air key".bold()) \(id.substringTo(8))", urgent: true)
			if let airkey = connectToAirKey() {
//                if self.certificate == nil {
//                    SignedFile._cache[id] = .hardware(airkey, airkey.name ?? "air key")
//                } else {
//                    SignedFile._cache[id] = .hardwarePublicKey(airkey.publicKey, airkey.name ?? "air key")
//                }

				SignedFile._cache[id] = .hardware(airkey, id)
			}
		case "x509":
			if let key = certificate?.publicKey {
				SignedFile._cache[id] = .software(key)
			}
		case "yubikey":
			// the key id is the first 128 bits of the hmac value for the single-byte blob 0x00
			if let key = Yubikey4.shared(), let yubikey = Yubikey(key: key) {
				if id == yubikey.id {
					SignedFile._cache[id] = .hardware(yubikey, CommandLineOptions.yubikey_name ?? "")
				} else {
					error_func(file: self, message: "file was \(pastTenseVerb) with a different \("Yubikey".bold()) (\(id.substringTo(8)))")
				}
			} else {
				error_func(file: self, message: "\("Yubikey".bold()) \(id.substringTo(8)) not found")

				SignedFile._cache[id] = nil
			}
		case "password":
			if let key = getKeyFromPassword(prompt: "Password for '\(NSString(string: self.filename).lastPathComponent)': ", salt: saltData) {
				let keyid = key.0.data().secureHash(withKey: key.1, algorithm: .sha256).hex()
				if id == keyid {
					SignedFile._cache[id] = .software(key.0)
				} else {
					return nil
				}
			} else {
				return nil
			}
		case "keychain":
			if let key = SecKeychain.getSymmetricKey(named: id) {
				SignedFile._cache[id] = .software(key)
			} else if let key = SecKeychain.getPrivateKey(named: id) {
				SignedFile._cache[id] = .software(key)
			} else {
				return nil
			}
		default:
			return nil
		}
		
		self.key = SignedFile._cache[id]

		return self.key
	}

	lazy var keyType : String? = {
		if let signed_data = self.signedData {
			return signed_data.unsignedAttributes?["keytype"] as? String
		}

		return nil
	}()

	lazy var keyID : String? = {
		if let signed_data = self.signedData {
			return signed_data.unsignedAttributes?["keyid"] as? String
		}

		return nil
	}()

	lazy var key : Key? = {
		if let keytype = self.keyType, let keyid = self.keyID {
			return self.retrieve_key(params: ["keytype":keytype, "keyid":keyid])
		}
		
		return nil
	}()
	
	lazy var includePatterns:[String] = {
		return CommandLineOptions.include_patterns
	}()

	lazy var excludePatterns:[String] = {
		return CommandLineOptions.exclude_patterns
	}()

	lazy var tagshash : Data = {
		let url = URL(fileURLWithPath: self.filename)
		
		let tags = (url.tags() ?? []).sorted().reduce("", { s,x in "\(s),\(x)" }).data(using: .utf8)!
		
		return tags.secureHash(HASH_ALGORITHM)
	}()
	
	// TODO: handle per-file tags for folder hashes
	lazy var hash : Data = {
		if self.isDirectory {
			var results = [(String, Data)]()
			FileManager.default.processFilesInDirectory(self.filename, recursively: true) {
				file,data in
				let fileName = (file as NSString).lastPathComponent
				if self.includePatterns.count > 0 {
					if self.includePatterns.some({ fileName.matches($0) }) == false {
						return
					}
				}
				
				if self.excludePatterns.count > 0 {
					if self.excludePatterns.some({ fileName.matches($0) }) {
						return
					}
				}

				let url = URL(fileURLWithPath: file)
				let tags = (url.tags() ?? []).sorted().reduce("", { s,x in "\(s),\(x)" }).data(using: .utf8)!

				if CommandLineOptions.includeTags {
					results.append((file, data!.join(tags).secureHash(HASH_ALGORITHM)))
				} else {
					results.append((file, data!.secureHash(HASH_ALGORITHM)))
				}
			}
			// important to process files in a deterministic order
			results.sort { $0.0 < $1.0 }
			return results.reduce(Data(), { s,x in s.join(x.1).secureHash(HASH_ALGORITHM) })
		} else {
			let data = try! Data.mappedContentsOfFile(self.filename, cached: false)
			// TODO: also hash extended attributes?
			return data.secureHash(HASH_ALGORITHM)
		}
	}()
	
	// NOTE: 'hasSignedData' uses several lazy vars, so simply
	// reading this proeprty will kick off possibly-unexpected or undesired chain of events
	var hasSignedData : Bool {
		return self.cloudURL != nil || signedData != nil
	}
	
	// TODO: put NSUserName(), eg 'chris', in the detached signature file name
	// this allows multiple people to sign a file and have the detached sigs in the
	// same folder
	lazy var detachedSignature : DetachedSignature? = {
		if let path = CommandLineOptions.look_folders.flatMap({
			(path:String) -> String? in
			return FileManager.default.fileExists(atPath: "\(path)/\(self.filename).sig") ? path : nil }).first {
			if CommandLineOptions.force == false {
				info_func(file: self, message: "found detached signature '\(path)/\(self.filename).sig'")
			}
			return DetachedSignature(filename: "\(path)/\(self.filename).sig")
		}
		
		return nil
	}()
	
	// TODO: if attached and detached sigs both exist, which one takes precendence?
	lazy var signedData : SignedData? = {
		if let temp = self.detachedSignature?.signedhash {
			return temp
		} else if let jsondata = self.readExtendedAttribute(named: COM_CHRIS_XATTR_KEY_SIGNED_HASH) {
			return SignedData.from(json: jsondata)
		} else if let temp = self.cloudSignature?.signedhash {
			return temp
		}
		
		return nil
	}()
	
	lazy var certificate : SecCertificate? = {
		if let temp = self.detachedSignature?.certificate {
			return temp
		} else if let pem = self.readExtendedAttribute(named: COM_CHRIS_XATTR_KEY_CERTIFICATE) {
			if let certificateData = pem.string(using: .utf8)?.extractPemBlobs().first?.0 {
				if let certificate = SecCertificateCreateWithData(nil, certificateData as CFData), certificate.evaluate(trustingSelfSignedCertificates: true) != .invalid {
					return certificate
				}
			}
		} else if let temp = self.cloudSignature?.certificate {
			return temp
		}
		
		return nil
	}()
	
	lazy var timestamp : Data? = {
		if let temp = self.detachedSignature?.timestamp {
			return temp
		} else if let base64 = self.readExtendedAttribute(named: COM_CHRIS_XATTR_KEY_TIME_STAMP) {
			if let timestamp = Data(base64Encoded: base64) {
				return timestamp
			}
		} else if let temp = self.cloudSignature?.timestamp {
			return temp
		}
		
		return nil
	}()
	
	// TODO: use inode? that won't change if the file is moved
	lazy var filePathData : Data = {
		var temp:stat = stat()
		stat(self.filename, &temp)
		return temp.st_ino.data()
		//return (FileManager.default.currentDirectoryPath + "/" + self.filename).data(using: .utf8)!
	}()
	
	// TODO: should 'tagshash' be included?
	lazy var encryptionKey : SecKey? = {
		if let key = self.key {
			switch key {
			case .hardware(let key, _):
				return key.encryptionKey(forTag: self.hash)?.key
			default:
				return nil
			}
		}
		
		return nil
	}()

	// TODO: should 'tagshash' be included?
	lazy var hmacKey : Data? = {
		if let key = self.key {
			switch key {
			case .hardware(let key, _):
				return key.hmacKey(forTag: self.hash)
			default:
				return nil
			}
		}
		
		return nil
	}()

	lazy var cloudFolder : String? = {
		#if DEBUG_LOCAL_CLOUD
			return ProcessInfo().environment["STATTOO_CLOUD_FOLDER"]?.trim(charactersInString: "/")
		#else
			if let bucket = ProcessInfo().environment["AWS_BUCKET"] {
				return "s3://\(bucket)"
			}
		#endif
		
		return nil
	}()

	lazy var cloudOnly : Bool = {
		return self.readExtendedAttribute(named: COM_CHRIS_XATTR_KEY_SIGNED_HASH) == nil &&
				self.readExtendedAttribute(named: COM_CHRIS_XATTR_KEY_CLOUD_ID) != nil
	}()

	lazy var cloudURL : URL? = {
		if let url = self.readExtendedAttribute(named: COM_CHRIS_XATTR_KEY_CLOUD_ID) {
			return URL(string: url.string(using: .utf8)!)
		} else if let cloudFolder = self.cloudFolder, CommandLineOptions.verify, CommandLineOptions.cloud {
			return URL(string: "\(cloudFolder)/stattoo/\(self.cloudKey)")
		}
		
		return nil
	}()

	lazy var cloudKey : String = {
		guard let hmacKey = self.hmacKey else {
			fatal_func(message: "no hardware key available")
		}
		
		// TODO: should cloud key be random? would prevent recovery if cloud_id attribute were destroyed
		// TODO: should 'tagshash' be included?
		return self.hash
			.secureHash(withKey: hmacKey, algorithm: .sha256)
			.toBase64StringX()
		//.replacingStringsMatchingPattern("[\\/\\+\\=]", withString: "")
		//return String.randomWithPattern("[a-zA-Z0-9]{25}")
		//return self.hash.secureHash(withKey: self.filePathData, algorithm: .sha256).hex()
	}()
	
	lazy var cloudSignature : DetachedSignature? = {
		// don't try to load a cloud signature if we're forcing a new signature on the file
		if CommandLineOptions.force == false, let cloud_url = self.cloudURL {
			do {
				if let temp = try DetachedSignature.getFromCloud(for: self), case .signature(let sig) = temp {
					return sig
				} else {
					error_func(file: self, message: "failed to read cloud signature")
				}
			} catch {
				error_func(file: self, message: "failed to read cloud signature from \(cloud_url.absoluteString)")
			}
		}
		
		return nil
	}()
	
	func readExtendedAttribute(named name:String) -> Data? {
		return stattoo.readExtendedAttribute(named: name, from: self.filename)
	}
	
	func writeExtendedAttribtue(_ data:Data, named name:String) -> Bool {
		return stattoo.writeExtendedAttribtue(data, named: name, to: self.filename)
	}
	
	func deleteExtendedAttribute(named name:String) -> Bool {
		if readExtendedAttribute(named: name) != nil {
			return stattoo.deleteExtendedAttribtue(named: name, from: self.filename)
		}
		
		return true
	}

	public func tear() -> Bool {
		if let signedData = self.signedData {
			let newDetachedSignature = DetachedSignature(signedhash: signedData, certificate: self.certificate, timestamp: self.timestamp)

			do {
				if FileManager.default.fileExists(atPath: "\(self.filename).sig") == false {
					if try newDetachedSignature.write(filename: "\(self.filename).sig") {
						info_func(file: self, message: "created detached signature \(self.filename).sig")
						return true
					} else {
						return false
					}
				} else {
					error_func(file: self, message: "file '\(self.filename).sig' already exists")
				}
			} catch {
				
			}
		} else {
			error_func(file: self, message: "could not read signature")
		}
		
		return false
	}
	
	func save() -> Bool {
		let detached = CommandLineOptions.detached
		let cloud = CommandLineOptions.cloud
		
		// we've gotta at least have a plain old signature to save
		guard let signedData = signedData else {
			return false
		}

		var delete_result = true
		delete_result = deleteExtendedAttribute(named: COM_CHRIS_XATTR_KEY_SIGNED_HASH) && delete_result
		delete_result = deleteExtendedAttribute(named: COM_CHRIS_XATTR_KEY_TIME_STAMP) && delete_result
		delete_result = deleteExtendedAttribute(named: COM_CHRIS_XATTR_KEY_CERTIFICATE) && delete_result
		delete_result = deleteExtendedAttribute(named: COM_CHRIS_XATTR_KEY_CLOUD_ID) && delete_result
		
		if delete_result == false {
			warning_func(file: self, message: "failed to clear old signature")
		}

		func cloud_path() -> String {
			var CLOUD_FOLDER:String? = nil
			#if DEBUG_LOCAL_CLOUD
				CLOUD_FOLDER = ProcessInfo().environment["STATTOO_CLOUD_FOLDER"]
			#else
				if let bucket = ProcessInfo().environment["AWS_BUCKET"] {
					CLOUD_FOLDER = "s3://\(bucket)"
				}
			#endif

			if let folder = CLOUD_FOLDER {
				return "\(folder)/stattoo/\(self.cloudKey).sig"
			} else {
				fatal_func(message: "cloud folder environment variable not set")
			}
		}

		if detached {
			let detachedSignature = DetachedSignature(signedhash: signedData, certificate: certificate, timestamp: timestamp)
			
			if cloud {
				guard let encryptionKey = encryptionKey else {
					fatal_func(message: "key not available")
				}
				
				guard let hmacKey = hmacKey else {
					fatal_func(message: "key not available")
				}
				
				do {
					if let cloud_url = URL(string: cloud_path()) {
						if let path = try detachedSignature.write(url: cloud_url, encryptionKey: encryptionKey, hmacKey: hmacKey) {
							return self.writeExtendedAttribtue(path.data(using: .utf8)!, named: COM_CHRIS_XATTR_KEY_CLOUD_ID)
						} else {
							error_func(file: self, message: "failed to write cloud signature")
						}
					} else {
						error_func(file: self, message: "AWS environment variables not set")
					}
				} catch {
					error_func(file: self, message: "failed to write cloud signature")
				}
				
				return false
			} else {
				let result = (try? detachedSignature.write(filename: "\(filename).sig")) ?? false
				if result {
					return true
				} else {
					warning_func(file: self, message: "error writing to detached signature")
					
					return false
				}
			}
		} else {
			// TODO: what should we do when they force "overwrite" a detached sig
			// delete it? what if the sig file is also part of a wildcard expansion
			// that's being signed (ie, they're forcing new sigs on myfolder/* and
			// myfolder/* contains detached sigs for other files in that folder)
			try? FileManager.default.removeItem(atPath: "\(filename).sig")
		}
		
		var result:Bool = true
		result = result && writeExtendedAttribtue(signedData.toJSON(), named: COM_CHRIS_XATTR_KEY_SIGNED_HASH)
		
		if let certificate = certificate {
			result = result && writeExtendedAttribtue(certificate.data().pem(withIdentifier: "CERTIFICATE").data(using: .utf8)!, named: COM_CHRIS_XATTR_KEY_CERTIFICATE)
		}
		
		if let timestamp = timestamp {
			result = result && writeExtendedAttribtue(timestamp.base64EncodedData(), named: COM_CHRIS_XATTR_KEY_TIME_STAMP)
		}

		return result
	}
	
	func verify(skipNotaryVerification:Bool) -> (timestamp: (Date, String?, String?), signer: (name:String, certified:Bool), comment:String?)? {
		if let signedData = signedData {
			func evaluateSignedData(data:Data, skipNotaryVerification:Bool) -> (timestamp: (Date, String?, String?), signer: (name:String, certified:Bool), comment:String?)? {
				var timestamp:(Date,String?,String?)!
				var signer:(String,Bool)!
				var comment:String? = nil
				
				if let properties = [String:Any].fromJSON(data) {
					if let signedHash = SignedHash(properties: properties) {
						self.includePatterns = signedHash.includePatterns ?? self.includePatterns
						self.excludePatterns = signedHash.excludePatterns ?? self.excludePatterns
						
						if self.includePatterns.count > 0 {
							info_func(file: self, message: "including files matching: \(self.includePatterns.reduce("", { s,x in "\(s), \(x)" }).trim(charactersInString: ", ").replacingOccurrences(of: ".*", with: "*"))")
						}
						
						if self.excludePatterns.count > 0 {
							info_func(file: self, message: "excluding files matching: \(self.excludePatterns.reduce("", { s,x in "\(s), \(x)" }).trim(charactersInString: ", ").replacingOccurrences(of: ".*", with: "*"))")
						}
						
						if signedHash.hash.secureEquals(self.hash) == false {
							error_func(file: self, message: "invalid signature")
							return nil
						}

						if signedHash.tagshash.secureEquals(self.tagshash) == false {
							if CommandLineOptions.includeTags {
								error_func(file: self, message: "tags have been modified")
								return nil
							} else {
								warning_func(file: self, message: "tags have been modified")
							}
						}

						comment = signedHash.comment
						signer = (certificate?.subjectName ?? signedHash.signer, certificate?.evaluate(trustingSelfSignedCertificates: false) ?? .invalid == .valid)
						if let ts = self.timestamp, skipNotaryVerification == false {
							let ts = SecureTimestampedData(data: signedData.signature, timestampResponseData: ts, authorityUrl: URL(string: "https://www.apple.com")!)
							
							if let (data, time) = ts.verify() {
								// this secureEquals is redundant to the one performed by 'verify'
								if data.secureEquals(signedData.signature) {
									timestamp = (time, ts.authorityName, nil)
								} else {
									error_func(file: self, message: "invalid notarization (timestamp is inauthentic or does not match file)")
									timestamp = (signedHash.timestamp, nil, nil)
								}
							} else {
								error_func(file: self, message: "invalid notarization (timestamp is inauthentic or does not match file)")
								timestamp = (signedHash.timestamp, nil, nil)
							}
						} else if let cloudTimestamp = self.cloudSignature?.cloudTimestamp {
							timestamp = (cloudTimestamp, nil, self.cloudURL?.host)
						} else {
							timestamp = (signedHash.timestamp, nil, nil)
						}
					} else {
						return nil
					}
				} else {
					return nil
				}
				
				return (timestamp: timestamp, signer: signer, comment: comment)
			}
			
			if let key = self.key {
				var data:Data? = nil
				switch key {
				case .software(let key):
					data = signedData.verify(withKey: key)
				case .hardware(let key, _):
					let workItem = DispatchWorkItem {
						info_func(message: "touch the blue dot on your \("air key".bold()) to verify each file")
						SignedFile._once2 = false
					}
					
					defer {
						workItem.cancel()
					}
					
					if SignedFile._once2 {
						// DispatchQueue.global().asyncAfter(deadline: DispatchTime.now() + 3, execute: workItem)
					}
					
					data = signedData.verify(withKey: key)
				}
				
				if let data = data {
					//info_func(message: "verifying...")
					return evaluateSignedData(data: data, skipNotaryVerification: skipNotaryVerification)
				}
				
				error_func(file: self, message: "incorrect key or invalid signature")
				return nil
			} else {
				if self.keyType ?? "" == "password" {
					error_func(file: self, message: "incorrect password")
				} else if self.keyType ?? "" == "yubikey" {
					// error messages are emitted by retrieve_key()
					//error_func(file: self, message: "Yubikey not found")
				} else {
					error_func(file: self, message: "incorrect key")
				}
				return nil
			}
		} else {
			// error_func(file: self, message: "missing or invalid signature")
			return nil
		}
	}

	private func finishSigning() {
		var notary:String? = nil
		if let notaryUrl = CommandLineOptions.notarize, let signedDataSignature = signedData?.signature {
			let url = URL(string: notaryUrl) ?? SecureTimestampedData.DEFAULT_TIMESTAMP_AUTHORITY_URL_APPLE
			// the notarized timestamp is on the signature, so is tied also to the data hash
			// TODO: should the timestamp only be on the hash so it's useful in isolation?
			if let timestamp = signedDataSignature.secureTimestamp(url: url) {
				notary = timestamp.authorityName
				self.timestamp = timestamp.timestampResponseData
			} else {
				error_func(file: self, message: "failed to notarize signature")
			}
		} else {
			timestamp = nil
		}

		self.certificate = CommandLineOptions.cert
		
		if save() == false {
			error_func(file: self, message: "failed to sign file")
		} else {
			info_func(file: self, message: "\(CommandLineOptions.sign ? "signed" : "tagged")\(CommandLineOptions.signer)")
			
			if let notary = notary {
				info_func(file: self, message: "notarized by " + notary.bold())
			}
		}
	}
	
	static var _once = true
	static var _once2 = true
	static var _warning = false
	// TODO: pass in comment, notary URL, etc with property bag
	func sign(withKey key: Key) {
		self.key = key
		
		let comment = CommandLineOptions.comment
		var signedHash = SignedHash(hash: self.hash, tagshash: self.tagshash, timestamp: Date(), signer: NSFullUserName(), comment: comment)
		if self.isDirectory {
			signedHash.includePatterns = CommandLineOptions.include_patterns.count > 0 ? CommandLineOptions.include_patterns : nil
			signedHash.excludePatterns = CommandLineOptions.exclude_patterns.count > 0 ? CommandLineOptions.exclude_patterns : nil
		}
		
		switch key {
		case .software(let key):
			self.signedData = signedHash.sign(withKey: key)
		case .hardware(let key, _):
			let workItem = DispatchWorkItem {
				if CommandLineOptions.air {
					info_func(message: "touch the blue dot on your \("air key".bold()) to \(CommandLineOptions.sign ? "sign" : "tag") each file")
				} else {
					info_func(message: "touch the flashing button on your \(CommandLineOptions.yubikey_name!.bold()) to sign each file")
					SignedFile._warning = true
				}
				SignedFile._once2 = false
			}

			defer {
				workItem.cancel()
			}
			
			if SignedFile._once2 {
				DispatchQueue.global().asyncAfter(deadline: DispatchTime.now() + 3, execute: workItem)
			}

			var signeddata:SignedData? = nil
			if CommandLineOptions.sign {
				signeddata = signedHash.sign(withKey: key.privateKey)
			} else {
				signeddata = signedHash.sign(withKey: key)
			}
			
			if let signeddata = signeddata {
				self.signedData = signeddata
				if SignedFile._warning {
					info_func(message: "thank you")
					SignedFile._warning = false
				}
			} else {
				error_func(file: self, message: "failed to sign file \(SignedFile._warning ? "(did you touch the \("button".colorize(.Yellow).blinking())?)" : "")")
				return
			}
		}

		finishSigning()
	}
}
