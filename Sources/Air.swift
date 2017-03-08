//
//  Air.swift
//  stattoo
//
//  Created by Christopher Burns on 8/19/16.
//  Copyright © 2016 Christopher Burns. All rights reserved.
//

import Foundation
import Crypto
import MultipeerConnectivity
import Security
import Random
import Darwin

class AirKeyProtocol {
	public enum Command : UInt8 {
		case awaitingAuthorization = 1 // air key is waiting for user to give permission
		case receivedAuthorization = 2 // air key has received user permission
		case response = 3 // response from air key
		case requestTag = 4 // request HMAC-SHA256 of data
		case requestSignature = 5 // request ECDSA of data
		case requestCertificate = 6 // request certificate for signing key
		case requestSignatureVerification = 7 // request certificate for signing key
	}
	
	public static var awaitingAuthorization:(() -> ())? = nil
	public static var receivedAuthorization:(() -> ())? = nil
	public static var response:((Int, Data) -> ())? = nil
	
	public static func interpret(command:Data) {
		let parts = command.partitionWithSizes([1, 8], discardRemaining: false, copy: true)
		let n:UInt8 = parts[0].cast()!
		let seq:Int = parts[1].cast()!
		
		switch n {
		case 1:
			AirKeyProtocol.awaitingAuthorization?()
		case 2:
			AirKeyProtocol.receivedAuthorization?()
		case 3:
			AirKeyProtocol.response?(seq, parts[2])
		default:
			return
		}
	}

	class func requestTag<T>(packetID: Int, data: Data, f:(Data) -> T) -> T {
		return f(Data(bytes: [Command.requestTag.rawValue]).join(packetID.data()).join(data))
	}

	class func requestSignature<T>(packetID: Int, data: Data, f:(Data) -> T) -> T {
		return f(Data(bytes: [Command.requestSignature.rawValue]).join(packetID.data()).join(data))
	}

	class func requestCertificate<T>(packetID: Int, data: Data, f:(Data) -> T) -> T {
		return f(Data(bytes: [Command.requestCertificate.rawValue]).join(packetID.data()).join(data))
	}

	class func requestSignatureVerification<T>(packetID: Int, data: Data, f:(Data) -> T) -> T {
		return f(Data(bytes: [Command.requestSignatureVerification.rawValue]).join(packetID.data()).join(data))
	}

	class func sendDisconnect(_ f:(Data) -> ()) {
		f(Data(bytes: [0, 1, 2, 3]))
	}
}

fileprivate var _session:MCSession!
fileprivate var _peerID:MCPeerID!
fileprivate var _advertiser:MCNearbyServiceAdvertiser!
var _airKey:AirKey? = nil

class AirKey : NSObject, MCNearbyServiceAdvertiserDelegate, MCSessionDelegate, HardwareKey {
	
	var name:String? = nil

	func genericRequest(with data:Data) -> Data? {
		var result:Data? = nil
		let semaphore = DispatchSemaphore(value: 0)
		
		AirKeyProtocol.response = {
			seq, d in
			result = d
			semaphore.signal()
		}
		
		do {
			try self.session.send(data, toPeers: [self.connectedPeerID!], with: .reliable)
		} catch {
			print(error)
			
			return nil
		}
		
		semaphore.wait()
		
		return result
	}

	public class PublicAirKey : PublicHardwareKey {
		let airKey : AirKey
		
		public init(key:AirKey) {
			self.airKey = key
		}
		
		public func verify(signature:Data, for data: Data) -> Bool? {
			return _airKey?.verify(signature: signature, for: data)
		}
	}

	public class PrivateAirKey : PrivateHardwareKey {
		let airKey : AirKey
		
		public init(key:AirKey) {
			self.airKey = key
		}
		
		public var certificate: SecCertificate? {
			if let data = AirKeyProtocol.requestCertificate(packetID: 0, data: "com.chris.stattoo".data(using: .utf8)!, f: {
				data -> Data? in
				return airKey.genericRequest(with: data)
			}) {
				return SecCertificateCreateWithData(nil, data as CFData)
			}
			
			return nil
		}
		
		public func sign(data: Data) -> Data? {
			if let data = AirKeyProtocol.requestSignature(packetID: 0, data: data.secureHash(.sha512), f: {
				data -> Data? in
				return airKey.genericRequest(with: data)
			}) {
				return data
			}
			
			return nil
		}

		public func decrypt(data: Data) -> Data? {
			return nil
		}
	}
	
	lazy var privateKey : PrivateHardwareKey = {
		return PrivateAirKey(key:self)
	}()

	lazy var publicKey : PublicAirKey = {
		return PublicAirKey(key:self)
	}()

	let session:MCSession
	let peerID:MCPeerID
	var connectedPeerID:MCPeerID? = nil
	let secret:Data
	
	var connectionHandler : ((MCSession, MCPeerID) -> ())? = nil
	
	init(session:MCSession, peerID:MCPeerID) {
		self.session = session
		self.peerID = peerID
		self.secret = UInt.random(max: 9999).padded(4).data(using: .utf8)! // String.randomWithPattern("[a-zA-Z0-9]{3}").data(using: .utf8)!
		_advertiser.startAdvertisingPeer()
	}
	
	func disconnect() {
		AirKeyProtocol.sendDisconnect {
			try! session.send($0, toPeers: [connectedPeerID!], with: .reliable)
		}
		CFRunLoopRunInMode(CFRunLoopMode.defaultMode, 0.01, false)
		session.disconnect()
		self.connectedPeerID = nil
	}
	
	func showPairingCode() {
		info_func(message: "air key code: \(self.secret.string(using: .utf8)!.characters.map { String($0) }.joined(separator: " "))", urgent: true)
	}

	public var certificate: SecCertificate? {
		return privateKey.certificate
	}

	public func sign(data: Data) -> Data? {
		return privateKey.sign(data: data)
	}

	var packetCounter = 0
	public func hmac(data: Data) -> Data? {
		if let connectedPeerID = connectedPeerID {
			var result:Data? = nil
			let semaphore = DispatchSemaphore(value: 0)
			
			AirKeyProtocol.response = {
				seq, d in
				result = d
				semaphore.signal()
			}
			
			packetCounter += 1
			if let _ = AirKeyProtocol.requestTag(packetID: packetCounter, data: data.secureHash(.sha512), f: {
				data -> Bool? in
				
				do {
					try self.session.send(data, toPeers: [connectedPeerID], with: .reliable)
				} catch {
					print(error)
					
					return nil
				}
				
				return true
			}) { } else {
				return nil
			}
			
			semaphore.wait()

			return result
		}
		
		return nil
	}

	public func verify(signature: Data, for data: Data) -> Bool? {
		if let connectedPeerID = connectedPeerID {
			var result:Bool = false
			let semaphore = DispatchSemaphore(value: 0)
			
			AirKeyProtocol.response = {
				seq, d in
				let temp:UInt8 = d.cast()!
				result = temp == 1
				semaphore.signal()
			}
			
			packetCounter += 1
			if let _ = AirKeyProtocol.requestSignatureVerification(packetID: packetCounter, data: data.secureHash(.sha512).join(signature), f: {
				data -> Bool? in
				
				do {
					try self.session.send(data, toPeers: [connectedPeerID], with: .reliable)
				} catch {
					print(error)
					
					return nil
				}
				
				return true
			}) { } else {
				return nil
			}
			
			
			semaphore.wait()
			
			return result
		}
		
		return nil
	}

	func session(_ session: MCSession, didReceive data: Data, fromPeer peerID: MCPeerID) {
		AirKeyProtocol.interpret(command: data)
		//self.dataHandler?(data)
	}
	
	func session(_ session: MCSession, didReceive stream: InputStream, withName streamName: String, fromPeer peerID: MCPeerID) {
		
	}
	
//	@nonobjc func session(_ session: MCSession, didReceiveCertificate certificate: [Any]?, fromPeer peerID: MCPeerID, certificateHandler: (Bool) -> Void) {
//		//print("new session", peerID.displayName, certificate)
//		certificateHandler(true)
//	}
	
	func session(_ session: MCSession, didStartReceivingResourceWithName resourceName: String, fromPeer peerID: MCPeerID, with progress: Progress) {
		
	}
	
	func session(_ session: MCSession, didFinishReceivingResourceWithName resourceName: String, fromPeer peerID: MCPeerID, at localURL: URL, withError error: Error?) {
		
	}

	func session(_ session: MCSession, peer peerID: MCPeerID, didChange state: MCSessionState) {
		if state == .connected, (connectedPeerID == nil || connectedPeerID!.displayName == peerID.displayName) {
            info_func(message: "connected to \(peerID.displayName.bold())")
			
			connectedPeerID = peerID
			
			AirKeyProtocol.awaitingAuthorization = {
                info_func(message: "authenticate with your \("air key".bold())", urgent: true)
			}

			AirKeyProtocol.receivedAuthorization = {
				info_func(message: "thank you")
			}

			DispatchQueue.global().async {
				self.connectionHandler?(session, peerID)
			}
		}
	}
	
	func advertiser(_ advertiser: MCNearbyServiceAdvertiser, didReceiveInvitationFromPeer peerID: MCPeerID, withContext context: Data?, invitationHandler: @escaping (Bool, MCSession?) -> Void) {
		// TODO: use Data.pack/unpack
		if let context = context {
			let parts = context.partitionWithSizes([1], discardRemaining: false)
			
			if parts.count < 2 {
				invitationHandler(false, nil)
			}
			
			if let code:UInt8 = parts[0].cast(), code == 0 {
				let parts = parts[1].partitionWithSizes([4, 10], discardRemaining: false)
				
				if parts[0] == self.secret {
					//print("received valid invitation from peer '\(peerID.displayName)'. Connecting...")
					self.name = parts[1].hex()
					if CommandLineOptions.remember {
						SecKeychainAddGenericPassword(
							nil,
							UInt32("stattoo_airpair_\(parts[1].string(using: .utf8)!)".characters.count),
							"stattoo_airpair_\(parts[1].string(using: .utf8)!)",
							UInt32("stattoo_airpair_\(parts[1].string(using: .utf8)!)".characters.count),
							"stattoo_airpair_\(parts[1].string(using: .utf8)!)",
							UInt32(parts[2].string(using: .utf8)!.characters.count),
							parts[2].string(using: .utf8)!, nil)
					}
					
					invitationHandler(true, self.session)
				} else {
					error_func(message: "received invalid invitation from peer '\(peerID.displayName)'")
					invitationHandler(false, nil)
					fatal_func(message: "could not connect to air key")
				}
			} else if let code:UInt8 = parts[0].cast(), code == 1 {
				let parts = parts[1].partitionWithSizes([10], discardRemaining: false)
				
				if parts.count < 2 {
					invitationHandler(false, nil)
				}
				
				if let key = SecKeychain.getPassword("stattoo_airpair_\(parts[0].string(using: .utf8)!)") {
					if key == parts[1].string(using: .utf8)! {
						invitationHandler(true, self.session)
						return
					}
				}
				
				invitationHandler(false, nil)
			}
		}
	}
	
	func advertiser(_ advertiser: MCNearbyServiceAdvertiser, didNotStartAdvertisingPeer error: Error) {
		print("advertising error", error)
	}
}

func connectToAirKey() -> AirKey? {
	if _airKey?.connectedPeerID != nil {
		return _airKey
	}

	_peerID = MCPeerID(displayName: "\(Host.current().name!)")
	_session = MCSession(peer: _peerID, securityIdentity: nil, encryptionPreference: .required)
	_advertiser = MCNearbyServiceAdvertiser(peer: _peerID, discoveryInfo: nil, serviceType: "stattoo")
	_airKey = AirKey(session: _session, peerID: _peerID)
	_session.delegate = _airKey
	_advertiser.delegate = _airKey

	_airKey!.showPairingCode()
	let semaphre = DispatchSemaphore(value: 0)

	let rl = CFRunLoopGetCurrent()

	var warning = false
	let workItem = DispatchWorkItem {
		info_func(message: "waiting...")
		warning = true
	}

	DispatchQueue.global().asyncAfter(deadline: DispatchTime.now() + 10.0, execute: workItem)

	_airKey!.connectionHandler = {
		c,p in

		workItem.cancel()
		
		if warning {
			info_func(message: "thank you")
		}
		
		semaphre.signal()

		CFRunLoopStop(rl)
	}

	CFRunLoopRun()

	semaphre.wait()
	
	return _airKey
}
