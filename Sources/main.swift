import Darwin
import Foundation
import Fundamentals
import Random
import Crypto
import CryptoTokenKit

let COM_CHRIS_XATTR_KEY_TIME_STAMP = "stattoo.rfc3161"
let COM_CHRIS_XATTR_KEY_CERTIFICATE = "stattoo.x509"
let COM_CHRIS_XATTR_KEY_IS_SIGNATURE = "stattoo.is_signature"
let COM_CHRIS_XATTR_KEY_CLOUD_ID = "stattoo.cloud_id"
let HASH_ALGORITHM = HashAlgorithm.sha256

CommandLineOptions.parse()

var keyid:(String,String)! = CommandLineOptions.keyid
var signer:String = CommandLineOptions.signer

func info_func(file:SignedFile? = nil, message:String, urgent:Bool = false) {
	if CommandLineOptions.quiet == false || urgent {
		if let file = file {
			print("stattoo: \(file.filename.trim(charactersInString: "/"))\(file.isDirectory ? "/" : ""): \(message)")
		} else {
			print("stattoo: \(message)")
		}
	}
}

func warning_func(file:SignedFile? = nil, message:String) {
	if CommandLineOptions.info {
		return
	}
	
    if let file = file {
        print("stattoo: \(file.filename.trim(charactersInString: "/"))\(file.isDirectory ? "/" : ""): \("warning ".colorize(.Yellow))\(message)".colorize(.Default))
    } else {
        print("stattoo: \("warning ".colorize(.Yellow))\(message)".colorize(.Default))
    }
}

func error_func(file:SignedFile? = nil, message:String) {
	if CommandLineOptions.info {
		return
	}
	
	if let file = file {
		print("stattoo: \(file.filename.trim(charactersInString: "/"))\(file.isDirectory ? "/" : ""): \("error ".colorize(.Red))\(message)".colorize(.Default))
	} else {
		print("stattoo: \("error ".colorize(.Red))\(message)".colorize(.Default))
	}
}

func fatal_func(message:String) -> Never {
	print("stattoo: \("fatal ".colorize(.Red))\(message)".colorize(.Default))
	exit(1)
}

// codesign -vv -d /usr/local/bin/stattoo 2>&1 | grep Authority

// TODO: make this better
// TODO: also create man page
func usage() {
	print("usage: sign [-v] [--force] [--stdinpass | --keychain[=<item name>] | --password] [--notarize[=<TSA server URL>]] [input files...]")
	exit(0)
}

var inputs:[String] = []
if Int(optind) >= CommandLine.arguments.count {
	usage()
	exit(0)
} else {
	inputs = CommandLine.arguments[Int(optind)..<CommandLine.arguments.count].render()
}

func show_file_signature_verification_results(file:SignedFile, result:(timestamp: (Date, String?, String?), signer: (name:String, certified:Bool), comment:String?)) {
	if CommandLineOptions.oneline {
		var ms = String()
//		ms.append(file.filename + ": ")
		ms.append("valid ".bold())
		ms.append("\(result.signer.name)\(result.signer.certified ? " * " : " ")")
		ms.append("\((result.timestamp.0).stringWithFormat(.SQL))\(result.timestamp.1 != nil ? " * " : " ")")
		if let notarizationAuthorityName = result.timestamp.1 {
			ms.append("\(notarizationAuthorityName) * ")
		}
		if let comment = result.comment {
			ms.append("\"\(comment)\"")
		}
		info_func(file: file, message: ms)
	} else {
		info_func(file: file, message: "valid \(file.isSigned ? "signature" : "tag") ✔︎")
		//print("\t\("key".bold()): \(file.signedData!.unsignedAttributes!["keytype"]! as! String) \((file.signedData!.unsignedAttributes!["keyid"]! as! String).substringTo(8))")
		if file.isSigned {
            if result.signer.certified {
                print("\t\("signer".bold()): \(result.signer.name) *")
            } else {
                // put the name in quotation marks to emphasize the dubious nature of an untrusted certificate
                print("\t\("signer".bold()): \"\(result.signer.name)\"")
            }
		}
		// TODO: should timestamps from system clock be distinguishsed from RFC3161 or AWS timestamnps? ie, should a word other
		// than "timestamp" be used?
        print("\t\("timestamp".bold()): \((result.timestamp.0).stringWithFormat(.LongNews))\(result.timestamp.1 != nil ? " *" : result.timestamp.2 != nil ? " ∎" : "")")
		if let notarizationAuthorityName = result.timestamp.1 {
			print("\t\("notary".bold()): \(notarizationAuthorityName) *")
		} else if let witness = result.timestamp.2 {
			print("\t\("witness".bold()): \(witness) ∎")
		}
		if let comment = result.comment {
			print("\t\("comment".bold()): \(comment)")
		}
	}
}

func driver() {
	if inputs.count > 1 {
		info_func(message: "\(CommandLineOptions.verify ? "verifying" : (CommandLineOptions.sign ? "signing" : "tagging")) \(inputs.count) files")
	}
	
	for filename in inputs {
        if CommandLineOptions.hash {
            if let data = try? Data(contentsOf: URL(fileURLWithPath: filename)).secureHash(.sha256) {
                if let hash = Yubikey4.shared()?.oath.hmac(data: data, using: "stattoo") {
                    info_func(message: "\(filename): \(CommandLineOptions.alpha ? hash.toBase64StringY() : hash.hex())", urgent: true)
                }
            } else {
                if let hash = Yubikey4.shared()?.oath.hmac(data: filename.data(using: .utf8)!, using: "stattoo") {
                    info_func(message: "\"\(filename.abbreviate(to: 10))\": \(CommandLineOptions.alpha ? hash.toBase64StringY().substringTo(25) : hash.hex())", urgent: true)
                }
            }
            
            continue
        }
        
		// don't filter using include/exclude patterns
		// include/exclude only applies to folder hashing

		let file = SignedFile(filename: filename.trim(charactersInString: "/"))
		
        if CommandLineOptions.info {
            if let keytype = file.signedData?.unsignedAttributes?["keytype"] as? String, let keyid = file.signedData?.unsignedAttributes?["keyid"] as? String {
                switch keytype {
                case "yubikey":
                    info_func(file: file, message: "\(file.pastTenseVerb) with \("Yubikey".bold()) \(keyid.substringTo(8))")
                case "keychain":
                    info_func(file: file, message: "\(file.pastTenseVerb) with \("keychain item".bold()) \(keyid)")
                case "x509":
                    info_func(file: file, message: "\(file.pastTenseVerb) with \("certificate".bold()) \"\(file.certificate?.subjectName ?? "")\"")
                default:
                    break
                }
            } else {
                info_func(file: file, message: "unsigned", urgent: false)
            }
            
            continue
        }
        
		if file.isDetachedSignatureFile, CommandLineOptions.verify {
			continue
		}
		
		if file.exists == false {
			error_func(file: file, message: "file does not exist")
			
			continue
		} else if CommandLineOptions.verify, file.hasSignedData == false {
			info_func(file: file, message: "\(file.isDirectory ? "folder" : "file") is not signed or tagged")
			
			continue
		}
		
		if CommandLineOptions.tear {
			if file.tear() == false {
				error_func(file: file, message: "failed to create detached signature")
			}
		} else if CommandLineOptions.verify {
			let result = file.verify(skipNotaryVerification: CommandLineOptions.skipNotaryVerification)
			if let result = result, CommandLineOptions.quiet == false {
				show_file_signature_verification_results(file: file, result: result)
			}
		} else {
			if file.isDetachedSignatureFile {
				warning_func(file: file, message: "won't \(CommandLineOptions.sign ? "sign" : "tag") detached signature file")
			} else {
				if file.hasSignedData == false || CommandLineOptions.force {
					file.sign(withKey: CommandLineOptions.signing_key)
				} else {
					error_func(file: file, message: "\(file.isDirectory ? "folder" : "file") is already \(file.isSigned ? "signed" : "tagged") (use '--force' to overwrite)")
				}
			}
		}
	}
}

if CommandLineOptions.air {
	DispatchQueue.global().async {
		driver()

		_airKey?.disconnect()

		CFRunLoopStop(CFRunLoopGetMain())
	}

	CFRunLoopRun()
} else {
	driver()
}

