import XCTest
@testable import package

class packageTests: XCTestCase {
    func testExample() {
        // This is an example of a functional test case.
        // Use XCTAssert and related functions to verify your tests produce the correct results.
        XCTAssertEqual(package().text, "Hello, World!")
    }


    static var allTests : [(String, (packageTests) -> () throws -> Void)] {
        return [
            ("testExample", testExample),
        ]
    }
}
