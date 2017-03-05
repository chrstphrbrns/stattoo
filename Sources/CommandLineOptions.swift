//
//  CommandLineOptions.swift
//  stattoo
//
//  Created by Christopher Burns on 8/19/16.
//  Copyright © 2016 Christopher Burns. All rights reserved.
//

import Foundation
import Crypto
import Argon2
import MultipeerConnectivity
import Fundamentals

let PASSWORD_TYPE:CryptoApplicationType = .offline

// ~3s on a 2014 mbp, 2.5 GHz Intel Core i7
let ARGON2_TIME_COST:UInt32 = 200
let ARGON2_MEMORY_COST:UInt32 = 50_000 // 50 MB
let ARGON2_PARALLELISM:UInt8 = 2

extension Yubikey4 {
    public var keyID : String? {
        if let key = Yubikey4.shared()?.oath.key(using: "stattoo") {
            return key.sign(data: Data(bytes: [0]))!.hex().substringTo(32)
        }
        
        return nil
    }
}

enum Key {
    case software(SecKey)
    case hardware(HardwareKey, String)
}

public struct Yubikey : HardwareKey {
    let key : Yubikey4
    let pin : String
    let id : String
    
    let symmetricKey:SymmetricHardwareKey
    public let privateKey:PrivateHardwareKey
    
    init?(key:Yubikey4, pin:String = "") {
        self.key = key
        self.pin = pin
        
        if let key = key.oath.key(using: "stattoo", createIfMissing: true) {
            self.symmetricKey = key
        } else {
            return nil
        }
        
        self.privateKey = key.piv.key(using:.slot9c, pinDelegate: { return pin })
        
        if let id = key.keyID {
            self.id = id
        } else {
            return nil
        }
    }
    
    public var certificate: SecCertificate? {
        return privateKey.certificate
    }
    
    public func hmac(data: Data) -> Data? {
        return symmetricKey.sign(data: data)
    }
    
    public func sign(data: Data) -> Data? {
        return privateKey.sign(data: data)
    }
}

func getKeyFromPassword(prompt:String? = nil, salt: Data? = nil) -> (SecKey, Data)? {
	if let password = String(cString: getpass(prompt ?? "Password: "), encoding: .utf8) {
		info_func(message: "crunching password...")
		let bytes = UnsafeMutablePointer<UInt8>.allocate(capacity: 16)
		defer {
			bytes.deallocate(capacity: 16)
		}
		
		if let salt = salt ?? platformUUID().data(using: .utf8)?.join(NSUserName().data(using: .utf8)!) {
			if let data = argon2i(password.data(using: .utf8)!, salt, 32, ARGON2_TIME_COST, ARGON2_MEMORY_COST, ARGON2_PARALLELISM) {
				return (SecKey.withData(data), salt)
			}
		}
	}
	
	return nil
}

class CommandLineOptions {
	// the base encryption key is defined to be the HMAC-SHA256 hash of the single byte value 0x01
	// with the "stattoo" credential on the Yubikey
	public static func encryptionKey(withTag tag:Data) -> SecKey? {
		if let keymaterial = Yubikey4.shared()?.oath.hmac(data: Data(bytes: [1]), using: "stattoo") {
			// the base encryption key is tangled with a tag (which is a file hash in stattoo) to create
			// a per-file encryption key
			return SecKey.withData(keymaterial.secureHash(withKey: tag, algorithm: .sha256))
		}
		
        return nil
		// fatal_func(message: "Yubikey".bold() + " not available")
	}

	// the base HMAC key is defined to be the HMAC-SHA256 hash of the single byte value 0x02
	// with the "stattoo" credential on the Yubikey
	public static func hmacKey(withTag tag:Data) -> Data? {
		if let keymaterial = Yubikey4.shared()?.oath.hmac(data: Data(bytes: [2]), using: "stattoo") {
			// the base HMAC key is tangled with a tag (which is a file hash in stattoo) to create
			// a per-file HMAC key
			return keymaterial.secureHash(withKey: tag, algorithm: .sha256)
		}
		
        return nil
		// fatal_func(message: "Yubikey".bold() + " not available")
	}

	static var oneline = false
	static var verify = false
	static var tear = false
	static var info = false
	static var skipNotaryVerification = false
	static var force = false
	static var stdinpass = false
	static var password = false
	static var notarize:String? = nil
	static var comment:String? = nil
	static var keychain = ""
	static var detached = false
	static var cloud = false
	static var air = false
	static var quiet = false
	static var defaults = false
	static var sign = false
	static var includeTags = true
	static var remember = false
	static var include_patterns:[String] = []
	static var exclude_patterns:[String] = []
	static var look_folders:[String] = ["."]
    static var searchCloud = false
    static var hash = false
    static var alpha = false
    static var set = false

	static var keyid:(String,String)!
	static var cert:SecCertificate? = nil
	static var signer:String = " with "
	static var yubikey_name:String? = detect_yubikey() != nil ? "Yubikey" : nil
    static var setkey:String? = nil
	
	static var signing_key:Key!
	static var signing_salt:Data? = nil
	
	static func parse() {
		// let stdinpass_name = "stdinpass".cString(using: .utf8)
		let keychain_name = "keychain".cString(using: .utf8)
		let password_name = "password".cString(using: .utf8)
		let notarize_name = "notarize".cString(using: .utf8)
		let force_name = "force".cString(using: .utf8)
		let comment_name = "comment".cString(using: .utf8)
		let detached_name = "detached".cString(using: .utf8)
		let cloud_name = "cloud".cString(using: .utf8)
		let air_name = "air".cString(using: .utf8)
		let quiet_name = "quiet".cString(using: .utf8)
		let tear_name = "tear".cString(using: .utf8)
		let sign_name = "sign".cString(using: .utf8)
		let include_name = "include".cString(using: .utf8)
		let exclude_name = "exclude".cString(using: .utf8)
		let oneline_name = "oneline".cString(using: .utf8)
		let look_name = "look".cString(using: .utf8)
        let hash_name = "hash".cString(using: .utf8)
        let alpha_name = "alpha".cString(using: .utf8)
        let set_name = "set".cString(using: .utf8)
		// let default_name = "default".cString(using: .utf8)
		let info_name = "info".cString(using: .utf8)
		let remember_name = "remember".cString(using: .utf8)
		let named_options:[option] = [
			// option(name: stdinpass_name, has_arg: no_argument, flag: nil, val: 200),
			option(name: keychain_name, has_arg: optional_argument, flag: nil, val: 201),
			option(name: password_name, has_arg: no_argument, flag: nil, val: 202),
			option(name: notarize_name, has_arg: optional_argument, flag: nil, val: 203),
			option(name: force_name, has_arg: no_argument, flag: nil, val: 204),
			option(name: comment_name, has_arg: required_argument, flag: nil, val: 205),
			option(name: detached_name, has_arg: no_argument, flag: nil, val: 206),
			option(name: cloud_name, has_arg: no_argument, flag: nil, val: 207),
			option(name: air_name, has_arg: no_argument, flag: nil, val: 208),
			option(name: quiet_name, has_arg: no_argument, flag: nil, val: 209),
			option(name: tear_name, has_arg: no_argument, flag: nil, val: 210),
			option(name: sign_name, has_arg: no_argument, flag: nil, val: 211),
			option(name: include_name, has_arg: required_argument, flag: nil, val: 212),
			option(name: exclude_name, has_arg: required_argument, flag: nil, val: 213),
			option(name: oneline_name, has_arg: no_argument, flag: nil, val: 214),
			option(name: look_name, has_arg: required_argument, flag: nil, val: 215),
			// option(name: default_name, has_arg: no_argument, flag: nil, val: 216),
			option(name: info_name, has_arg: no_argument, flag: nil, val: 217),
			option(name: remember_name, has_arg: no_argument, flag: nil, val: 218),
			option(name: hash_name, has_arg: no_argument, flag: nil, val: 219),
			option(name: set_name, has_arg: optional_argument, flag: nil, val: 220),
			option(name: alpha_name, has_arg: no_argument, flag: nil, val: 221),
			option()
		]
		
		let file = NSString(string: "~/.stattoo").expandingTildeInPath

		var unsafeArgs = CommandLine.unsafeArgv
		let args:[String] = [] // (try? String(contentsOfFile: file).components(separatedBy: " ")) ?? []
		if args.count > 0 {
			unsafeArgs = UnsafeMutablePointer<UnsafeMutablePointer<Int8>?>.allocate(capacity: Int(CommandLine.argc) + args.count)
			var i = 1
			unsafeArgs[0] = CommandLine.unsafeArgv[0]!
			args.each {
				s in
				s.withCString {
					let temp = NSData(bytes: $0, length: s.utf8.count + 1) as Data
					unsafeArgs[i] = temp.unsafeBytePointer.mutable.int8
				}
				
				i += 1
			}
			(unsafeArgs + i).assign(from: CommandLine.unsafeArgv + 1, count: CommandLine.argc - 1)
		}
		
		let yubikey_id = Yubikey4.shared()?.keyID
		
		var op:Int32 = getopt_long(Int32(Int(CommandLine.argc) + args.count), unsafeArgs, "vVTk::p", named_options, nil)
		while op != -1 {
			if op == Int32("v".unicodeScalars.first!.value) {
				CommandLineOptions.verify = true
				CommandLineOptions.skipNotaryVerification = false
			} else if op == Int32("V".unicodeScalars.first!.value) {
				CommandLineOptions.verify = true
				CommandLineOptions.skipNotaryVerification = true
			} else if op == Int32("T".unicodeScalars.first!.value) {
				CommandLineOptions.includeTags = false
			} else if op == Int32("p".unicodeScalars.first!.value) {
				CommandLineOptions.password = true
			} else if op == 200 {
				CommandLineOptions.stdinpass = true
			} else if op == Int32("k".unicodeScalars.first!.value) || op == 201 {
				if optarg != nil {
					CommandLineOptions.keychain = String(cString: optarg).trim(charactersInString: "=")
				} else {
					CommandLineOptions.keychain = "stattoo"
				}
			} else if op == 202 {
				CommandLineOptions.password = true
			} else if op == 203 {
				if optarg != nil {
					CommandLineOptions.notarize = String(cString: optarg)
				} else {
					CommandLineOptions.notarize = ""
				}
			} else if op == 204 {
				CommandLineOptions.force = true
			} else if op == 205 {
				if optarg != nil {
					CommandLineOptions.comment = String(cString: optarg).trim(charactersInString: "=")
				}
			} else if op == 206 {
				CommandLineOptions.detached = true
			} else if op == 207 {
//				if yubikey_name != nil {
					CommandLineOptions.cloud = true
//				} else {
//					fatal_func(message: "Yubikey".bold() + " not available")
//				}
				CommandLineOptions.detached = true
			} else if op == 208 {
				CommandLineOptions.air = true
			} else if op == 209 {
				CommandLineOptions.quiet = true
			} else if op == 210 {
				CommandLineOptions.tear = true
			} else if op == 211 {
				CommandLineOptions.sign = true
			} else if op == 212 {
				if optarg != nil {
					CommandLineOptions.include_patterns.append(
						String(cString: optarg)
							.trim(charactersInString: "="))
				}
			} else if op == 213 {
				if optarg != nil {
					CommandLineOptions.exclude_patterns.append(
						String(cString: optarg)
							.trim(charactersInString: "="))
				}
			} else if op == 214 {
				CommandLineOptions.oneline = true
			} else if op == 215 {
				if optarg != nil {
					CommandLineOptions.look_folders.append(String(cString: optarg).trim(charactersInString: "/"))
				}
			} else if op == 216 {
				CommandLineOptions.defaults = true
			} else if op == 217 {
				CommandLineOptions.info = true
			} else if op == 218 {
				CommandLineOptions.remember = true
            } else if op == 219 {
                CommandLineOptions.hash = true
            } else if op == 220 {
                CommandLineOptions.set = true
                if optarg != nil {
                    CommandLineOptions.setkey = String(cString: optarg)
                }
            } else if op == 221 {
                CommandLineOptions.alpha = true
			} else {
				break
			}
			
			op = getopt_long(Int32(Int(CommandLine.argc) + args.count), unsafeArgs, "vVTk::p", named_options, nil)
		}
		
		//CommandLineOptions.encryption_key = SecKeychain.getSymmetricKey(named: "stattoo") ?? SecKey.random(named: "stattoo")!

		optind -= Int32(args.count)
		
		if verify {
			return
		}
        
        if hash, Yubikey4.shared() == nil {
            fatal_func(message: "\("Yubikey".bold()) not found")
        }

        if cloud, Yubikey4.shared() == nil, air == false {
            fatal_func(message: "cloud signatures require a hardware key")
        }

        // stattoo --force --set "$(head -c 32 /dev/random | xxd -p | tr -d "\n")"
        if set {
            if force {
                func getkey() -> String {
                    let ptr = UnsafeMutablePointer<Int8>.allocate(capacity: 65)
                    ptr.initialize(to: 0, count: 65)
                    print("Enter key (exactly 64 hex digits, or nothing to use a random key): ", terminator: "")
                    let temp = fgets(ptr, 65, stdin)
                    if strnlen(temp, 64) <= 1 {
                        return Data.random(32).hex()
                    } else {
                        return String(bytesNoCopy: temp!, length: 64, encoding: .utf8, freeWhenDone: false)!
                    }
                }
                
                let key = setkey ?? getkey()
                
                if let yubikey = Yubikey4.shared()?.oath {
                    if let hexkey = Data.fromHex(key) {
                        if hexkey.count == 32 {
                            let _ = yubikey.set(credential: "stattoo", withKey: hexkey)
                        } else {
                            error_func(message: "key must have 64 hex digits")
                        }
                    } else {
                        error_func(message: "key must be a valid 64 digit hex value")
                    }
                } else {
                    fatal_func(message: "\("Yubikey".bold()) not found")
                }
            } else {
                error_func(message: "must use --force with --set")
                warning_func(message: "setting a new key will invalidate all tags and hashes made with the current key")
            }
            
            exit(0)
        }
        
		if defaults {
			var args:[String] = []
			
			if cloud {
				args.append("--cloud")
			}
			
			// "." is included by default, so only count other folders
			if look_folders.count > 1 {
				args.append(contentsOf: ["--look", look_folders[0]])
			}
			
			if force {
				args.append("--force")
			}
			
			if detached {
				args.append("--detached")
			}
			
			if include_patterns.count > 0 {
				args.append(contentsOf: ["--include", include_patterns[0]])
			}

			if exclude_patterns.count > 0 {
				args.append(contentsOf: ["--exclude", exclude_patterns[0]])
			}
			
			try! args.joined(separator: " ").write(toFile: file, atomically: true, encoding: .utf8)
			
			exit(0)
		}
		
		include_patterns = include_patterns.map {
			$0
				.replacingOccurrences(of: "*", with: ".*")
				.replacingOccurrences(of: "?", with: ".?")
		}

		exclude_patterns = exclude_patterns.map {
			$0
				.replacingOccurrences(of: "*", with: ".*")
				.replacingOccurrences(of: "?", with: ".?")
		}

		if CommandLineOptions.stdinpass == true {
			fatal_func(message: "invalid option")
		} else if CommandLineOptions.keychain != "" {
			if CommandLineOptions.verify == false, let identity = SecKeychain.getIdentity(named: CommandLineOptions.keychain) {
				if let privateKey = identity.privateKey(), let certificate = identity.certificate() {
					//print(SecCertificateCopyValues(certificate, nil, nil))
					//print(certificate.fingerprint(algorithm: .sha1).hex())
					CommandLineOptions.signing_key = .software(privateKey)
					CommandLineOptions.keyid = ("x509", certificate.fingerprint(algorithm: .sha1).hex())
					CommandLineOptions.cert = certificate
					if let cert = CommandLineOptions.cert {
						if cert.evaluate(trustingSelfSignedCertificates: true) == .invalid {
							fatal_func(message: "invalid certificate")
						}
					} else {
						fatal_func(message: "failed to read certificate")
					}
				} else {
					fatal_func(message: "failed to read certificate or private key")
				}
				info_func(message: "found keychain item \(keychain.bold())")
			} else if let skey = SecKeychain.getSymmetricKey(named: CommandLineOptions.keychain) {
				CommandLineOptions.signing_key = .software(skey)
				CommandLineOptions.keyid = ("keychain", CommandLineOptions.keychain)
				info_func(message: "found keychain item \(keychain.bold())")
			} else if CommandLineOptions.keychain == "stattoo" {
				if let skey = SecKey.random(named: "stattoo") {
					CommandLineOptions.signing_key = .software(skey)
					CommandLineOptions.keyid = ("keychain", CommandLineOptions.keychain)
				} else {
					fatal_func(message: "error: could not create keychain item \(CommandLineOptions.keychain.bold())")
				}
				info_func(message: "found keychain item \(keychain.bold())")
			} else {
				fatal_func(message: "error: keychain item \(CommandLineOptions.keychain.bold()) not found")
			}
			
			CommandLineOptions.signer += "keychain item \(CommandLineOptions.keychain.bold())"
		} else if air {
			info_func(message: "connect with your " + "air key".bold())
			if let airKey = connectToAirKey() {
				// TODO: make this use the actual air key certificate
                if sign {
                    if let certificate = airKey.privateKey.certificate {
                        CommandLineOptions.signer += "air key ".bold() + (airKey.name ?? "").substringTo(8)
                        CommandLineOptions.signing_key = .hardware(airKey, "air")
                        CommandLineOptions.cert = certificate
                        CommandLineOptions.keyid = ("air",  airKey.name!)
                        // CommandLineOptions.keyid = ("air", airKey.name!)
                    } else {
                        fatal_func(message: "failed to retrieve \("air key".bold()) certificate")
                    }
				} else {
					CommandLineOptions.signer += "air key ".bold() + (airKey.name ?? "").substringTo(8)
					CommandLineOptions.signing_key = .hardware(airKey, "air")
					CommandLineOptions.keyid = ("air", airKey.name!)
				}
			} else {
				fatal_func(message: "failed to connect to \("air key".bold())")
			}
		} else if CommandLineOptions.password == true || CommandLineOptions.yubikey_name == nil, info == false {
			if sign {
				fatal_func(message: "cannot sign with a password")
			}
			
			if let key = getKeyFromPassword() {
				signing_salt = key.1
				CommandLineOptions.signing_key = .software(key.0)
				// the key id is the first 128 bits of the hmac value for the single-byte blob 0x00
				CommandLineOptions.keyid = ("password", key.0.data().secureHash(withKey: key.1, algorithm: .sha256).hex())
			} else {
				fatal_func(message: "failed to read password")
			}
			CommandLineOptions.signer += "password".bold()
		} else if let yubikey_name = CommandLineOptions.yubikey_name, sign {
			info_func(message: "found \(yubikey_name.bold()) \(yubikey_id!.substringTo(8))")
			var pin = SecKeychain.getPassword("stattoo_yubikey_pin")
			if pin == nil {
				if let temp = String(cString: getpass("Enter Yubikey PIN: "), encoding: .utf8) {
					SecKeychainAddGenericPassword(nil, UInt32("stattoo_yubikey_pin".characters.count), "stattoo_yubikey_pin", UInt32("stattoo".characters.count), "stattoo", UInt32(temp.characters.count), temp, nil)
					pin = temp
				}
			}

            if let yk = Yubikey4.shared(), let pin = pin, let key = Yubikey(key: yk, pin: pin), let certificate = key.certificate {
                CommandLineOptions.signing_key = .hardware(key, yubikey_name)
                CommandLineOptions.keyid = ("yubikey", key.id)
                
                CommandLineOptions.signer += yubikey_name.bold() + " \(yubikey_id!.substringTo(8))"
                CommandLineOptions.cert = certificate
			} else {
				fatal_func(message: "sorry")
			}
		} else if let yubikey_name = CommandLineOptions.yubikey_name, info == false {
			if let yk = Yubikey4.shared(), let key = Yubikey(key: yk) {
				CommandLineOptions.signing_key = .hardware(key, yubikey_name)
				// the key id is the first 128 bits of the hmac value for the single-byte blob 0x00
				CommandLineOptions.keyid = ("yubikey", yubikey_id!)
				info_func(message: "found \(yubikey_name.bold()) \(keyid.1.substringTo(8))")
			} else {
				print("error: yubikey failure")
				exit(1)
			}
			
			CommandLineOptions.signer += yubikey_name.bold() + " \(keyid.1.substringTo(8))"
		}
	}
}




