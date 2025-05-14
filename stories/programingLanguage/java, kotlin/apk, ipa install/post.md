# apk, ipa install on kotlin server

apk just download on s3 but ipa is not

download to ipa for you have to create plist file that is support ipa downloadble file

you have to ipa path and file name and bundleIdentifier , appTitle

this parameter need to make plist file for ipa download

```kotlin
fun createPlistByIpaData(
    fileName: String,
    ipaPath: String,
    bundleIdentifier: String,
    appTitle: String
): MultipartFile {
    val plistContent = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
          <key>items</key>
          <array>
            <dict>
              <key>assets</key>
              <array>
                <dict>
                  <key>kind</key>
                  <string>software-package</string>
                  <key>url</key>
                  <string>$ipaPath</string>
                </dict>
              </array>
              <key>metadata</key>
              <dict>
                <key>bundle-identifier</key>
                <string>$bundleIdentifier</string>
                <key>bundle-version</key>
                <string>1.0.0</string>
                <key>kind</key>
                <string>software</string>
                <key>subtitle</key>
                <string>Company Name</string>
                <key>title</key>
                <string>$appTitle</string>
              </dict>
            </dict>
          </array>
        </dict>
        </plist>
    """.trimIndent()

    val file = File(fileName)
    file.printWriter().use { writer ->
        writer.println(plistContent)
    }

    val multipartFile: MultipartFile
    FileInputStream(file).use { inputStream ->
        multipartFile = MockMultipartFile(
            file.name,                      // 파일 이름
            file.name,                      // 원본 파일 이름
            "text/xml",              // 컨텐츠 타입
            inputStream                     // 파일 데이터
        )
    }
    if (file.exists()) {
        file.delete()  // 파일 삭제
    }
    return multipartFile
}

```

if you create this blabal.plist file you can save this file whenever

how can you get ipa, apk detail data you can get this method

```kotlin
@Configuration
class AppMetaData(
    private val s3FileManager: S3FileManager,
) {

    fun getIpaMetaData(file: MultipartFile, userId: String): GetAppMetaDataDto {
        val zipInputStream = ZipInputStream(ByteArrayInputStream(file.bytes))
        val minimumOs = ""
        var shortVersion = ""
        var appTitle = ""
        var versionCode = ""
        var minOsVersion = ""
        var bundleIdentifier = ""
        while (true) {
            val entry = zipInputStream.nextEntry ?: break
            if (entry.name.endsWith("Info.plist")) {
                val plistContent = zipInputStream.readBytes()
                try {
                    val plist = PropertyListParser.parse(ByteArrayInputStream(plistContent)) as NSDictionary
                    shortVersion = plist.objectForKey("CFBundleShortVersionString")?.toString() ?: shortVersion
                    versionCode = plist.objectForKey("CFBundleVersion")?.toString() ?: versionCode
                    minOsVersion = plist.objectForKey("MinimumOSVersion")?.toString() ?: minOsVersion
                    bundleIdentifier = plist.objectForKey("CFBundleIdentifier")?.toString() ?: bundleIdentifier
                    appTitle =
                        plist.objectForKey("CFBundleDisplayName")?.toString() ?: plist.objectForKey("CFBundleName")
                            ?.toString() ?: appTitle

                } catch (e: Exception) {
                    logger().info("getIpaMetaData zipInputStream.nextEntry $e")
                    throw AppHubException(ErrorCodes.IPA_DATA_ERROR)
                }
            }
        }
        zipInputStream.close()
        val minimumSdk = ""
        val version = "${shortVersion}(${versionCode})"

        val size = file.size.toString()
        val md5 = file.md5()
        val originalName: String = file.originalFilename ?: throw AppHubException(ErrorCodes.FILE_NO_HAVE_NAME)
        val fileExtension: AppExtensionType = AppExtensionType.fromExtension(
            originalName.substringAfterLast(".", "").lowercase()
        )

        return GetAppMetaDataDto(
            originalName = originalName,
            minimumOs = minimumOs,
            minimumSdk = minimumSdk,
            version = version,
            md5 = md5,
            fileExtension = fileExtension,
            size = size,
            bundleIdentifier = bundleIdentifier,
            appTitle = appTitle,
            s3FileName = "",
        )
    }

    fun getApkMetaData(file: MultipartFile, userId: String): GetAppMetaDataDto {
        val minimumOs = ""
        var version: String
        var minimumSdk: String


        val tempFile = File.createTempFile("meta", ".apk")
        val byteArray = file.inputStream.readBytes()
        val byteArrayInputStream = ByteArrayInputStream(byteArray)
        byteArrayInputStream.copyTo(tempFile.outputStream())
        ApkFile(tempFile).use { apkFile ->
            val meta = apkFile.apkMeta
            version = "${meta.versionName}(${meta.versionCode})"
            minimumSdk = meta.minSdkVersion
        }
        tempFile.delete()


        val originalName: String = file.originalFilename ?: throw AppHubException(ErrorCodes.FILE_NO_HAVE_NAME)
        val fileExtension: AppExtensionType = AppExtensionType.fromExtension(
            originalName.substringAfterLast(".", "").lowercase()
        )


        val size = file.size.toString()
        val md5 = file.md5()

        return GetAppMetaDataDto(
            originalName = originalName,
            minimumOs = minimumOs,
            minimumSdk = minimumSdk,
            version = version,
            md5 = md5,
            fileExtension = fileExtension,
            size = size,
            bundleIdentifier = "",
            appTitle = "",
            s3FileName = "",
        )
    }
}
```

play app on ios, you have to use plist prabably and than this thing is not normaly
the reason why write this document
