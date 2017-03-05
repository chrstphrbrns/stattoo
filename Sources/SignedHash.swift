//
//  SignedHash.swift
//  stattoo
//
//  Created by Christopher Burns on 8/19/16.
//  Copyright © 2016 Christopher Burns. All rights reserved.
//

import Foundation
import Crypto
import Security

let COM_CHRIS_XATTR_KEY_SIGNED_HASH = "stattoo.signedhash"

struct SignedHash {
	var properties:[String:Any] = [:]
	
	var timestamp:Date {
		didSet {
			properties["timestamp"] = Int(timestamp.timeIntervalSinceReferenceDate)
		}
	}

	var tagshash:Data {
		didSet {
			properties["tagshash"] = tagshash.hex()
		}
	}

	var hash:Data {
		didSet {
			properties["hash"] = hash.hex()
		}
	}
	
	var signer:String {
		didSet {
			properties["signer"] = signer
		}
	}
	
	var comment:String? {
		didSet {
			properties["comment"] = comment
		}
	}
	
	var includePatterns:[String]? {
		didSet {
			properties["include"] = includePatterns
		}
	}

	var excludePatterns:[String]? {
		didSet {
			properties["exclude"] = excludePatterns
		}
	}

	init(hash:Data, tagshash:Data, timestamp:Date, signer:String, comment:String? = nil, includeFilters:[String]? = nil, excludeFilters:[String]? = nil) {
		self.hash = hash
		self.properties["hash"] = hash.hex()

		self.tagshash = tagshash
		self.properties["tagshash"] = tagshash.hex()

		self.timestamp = timestamp
		self.properties["timestamp"] = Int(timestamp.timeIntervalSinceReferenceDate)
		
		self.signer = signer
		self.properties["signer"] = signer
		
		if let comment = comment {
			self.comment = comment
			self.properties["comment"] = comment
		} else {
			self.comment = nil
		}

		if let includeFilters = includeFilters {
			self.includePatterns = includeFilters
			self.properties["include"] = includeFilters
		} else {
			self.includePatterns = nil
		}

		if let excludeFilters = excludeFilters {
			self.excludePatterns = excludeFilters
			self.properties["exclude"] = excludeFilters
		} else {
			self.excludePatterns = nil
		}
	}
	
	init?(properties:[String:Any]) {
		guard let hash = properties["hash"] as? String else {
			return nil
		}

		if let hashData = Data.fromHex(hash) {
			self.hash = hashData
			self.properties["hash"] = hashData
		} else {
			return nil
		}

		guard let tagshash = properties["tagshash"] as? String else {
			return nil
		}

		if let tagshashData = Data.fromHex(tagshash) {
			self.tagshash = tagshashData
			self.properties["tagshash"] = tagshashData
		} else {
			return nil
		}

		guard let timestamp = properties["timestamp"] as? Int else {
			return nil
		}
		
		self.timestamp = Date(timeIntervalSinceReferenceDate: TimeInterval(timestamp))
		self.properties["timestamp"] = timestamp
		
		guard let signer = properties["signer"] as? String else {
			return nil
		}
		
		self.signer = signer
		self.properties["signer"] = signer
		
		if let comment = properties["comment"] as? String {
			self.comment = comment
			self.properties["comment"] = comment
		} else {
			self.comment = nil
		}
		
		if let includeFilters = properties["include"] as? [String] {
			self.includePatterns = includeFilters
			self.properties["include"] = includeFilters
		} else {
			self.includePatterns = nil
		}
		
		if let excludeFilters = properties["exclude"] as? [String] {
			self.excludePatterns = excludeFilters
			self.properties["exclude"] = excludeFilters
		} else {
			self.excludePatterns = nil
		}
	}
	
	func sign(withKey key:HardwareKey) -> SignedData? {
		// TODO: store argon2 parameters with password
		let unsignedAttributes:[String:Any] = ["keytype": keyid.0, "keyid": keyid.1]
		
		return SignedData.sign(data: properties.toJSON(), withKey: key, algorithm: HASH_ALGORITHM, unsignedAttributes: unsignedAttributes)
	}

	func sign(withKey key:PrivateHardwareKey) -> SignedData? {
        let unsignedAttributes = ["keytype": "x509", "keyid": key.certificate!.fingerprint(algorithm: .sha1).hex()]
		
		return SignedData.sign(data: properties.toJSON(), withKey: key, unsignedAttributes: unsignedAttributes)
	}

	func sign(withKey key:SecKey) -> SignedData? {
		var unsignedAttributes:[String:Any] = ["keytype": keyid.0, "keyid": keyid.1]

        if CommandLineOptions.sign {
            unsignedAttributes["keytype"] = "x509"
            unsignedAttributes["keyid"] = CommandLineOptions.cert!.fingerprint(algorithm: .sha1).hex()
        }
        
		if let salt = CommandLineOptions.signing_salt {
			unsignedAttributes["salt"] = salt.hex()
		}

		return SignedData.sign(data: properties.toJSON(), withKey: key, algorithm: HASH_ALGORITHM, unsignedAttributes: unsignedAttributes)
	}
}
