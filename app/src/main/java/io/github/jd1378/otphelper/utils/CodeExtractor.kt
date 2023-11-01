package io.github.jd1378.otphelper.utils

class CodeExtractor {
  companion object {
    private val sensitiveWords =
        listOf(
            "code",
            "کد",
            "رمز",
            "\\bOTP\\b",
            "\\b2FA\\b",
            "Einmalkennwort",
            "contraseña",
            "c[oó]digo",
            "clave",
            "验证码",
            "識別碼",
            "認證",
            "驗證",
            "код",
            "סיסמ",
            "קוד",
            "\\bKodu\\b",
            "\\bKodunuz\\b",
            "\\bTAN\\b",
            "\\bmTAN\\b",
        )

    private val ignoredWords =
        listOf(
            "مقدار",
            "مبلغ",
            "amount",
            "برای",
            "-ارز",
            // avoids detecting space separated code as bunch of words:
            "[a-zA-Z0-9] [a-zA-Z0-9] [a-zA-Z0-9] [a-zA-Z0-9] ?",
        )

    private val generalCodeMatcher =
        """(?:${sensitiveWords.joinToString("|")})(?:\s*(?!${
                ignoredWords.joinToString("|")
            })[^\s:.'"\d\u0660-\u0669\u06F0-\u06F9])*[:.]?\s*(["']?)${""
              // this comment is to separate parts
          }(?<code>[\d\u0660-\u0669\u06F0-\u06F9a-zA-Z]{4,}|(?: [\d\u0660-\u0669\u06F0-\u06F9a-zA-Z]){4,}|)\1(?:[.\s][\n\t]|[.,，]|${'$'})"""
            .toRegex(
                setOf(
                    RegexOption.IGNORE_CASE,
                    RegexOption.MULTILINE,
                ))

    private val specialCodeMatcher =
        """(?<code>[\d\u0660-\u0669\u06F0-\u06F9 ]{4,}(?=\s)).*(?:${sensitiveWords.joinToString("|")})"""
            .toRegex(setOf(RegexOption.IGNORE_CASE, RegexOption.MULTILINE))

    fun getCode(str: String): String? {
      val sensitiveWordsRegex = sensitiveWords.joinToString("|")
            val pattern = """(?<=($sensitiveWordsRegex)\s*:?\s*)\b([\d\u0660-\u0669\u06F0-\u06F9a-zA-Z ]{4,})\b""".toRegex(setOf(RegexOption.IGNORE_CASE))
            val match = pattern.find(str)
            return match?.value
    }

    private fun toEnglishNumbers(number: String?): String? {
      if (number.isNullOrEmpty()) return null
      val chars = CharArray(number.length)
      for (i in number.indices) {
        var ch = number[i]
        if (ch.code in 0x0660..0x0669) {
          ch -= (0x0660 - '0'.code)
        } else if (ch.code in 0x06f0..0x06F9) {
          ch -= (0x06f0 - '0'.code)
        }
        chars[i] = ch
      }
      return String(chars)
    }
  }
}
