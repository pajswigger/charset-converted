package burp

import java.nio.charset.Charset


data class MessageInfo(val headers: MutableList<String>, val body: ByteArray)

class BurpExtender : IBurpExtender, IProxyListener, IHttpListener {
    companion object {
        val CONTENT_TYPE = "Content-Type: "
        val CHARSET = Regex("charset=(\\S+)")
        val ORIGINAL_CHARSET = "X-Original-Charset: "
    }

    lateinit var callbacks: IBurpExtenderCallbacks

    override fun registerExtenderCallbacks(callbacks: IBurpExtenderCallbacks) {
        this.callbacks = callbacks
        callbacks.setExtensionName("Charset Converter")
        callbacks.registerProxyListener(this)
        callbacks.registerHttpListener(this)
    }

    override fun processProxyMessage(isRequest: Boolean, proxyMessage: IInterceptedProxyMessage) {
        try {
            if (isRequest) {
                val rc = processInbound(parseRequest(proxyMessage.messageInfo.request))
                if(rc != null) {
                    proxyMessage.messageInfo.request = rc
                }
            } else {
                val rc = processOutbound(parseResponse(proxyMessage.messageInfo.response))
                if (rc != null) {
                    proxyMessage.messageInfo.response = rc
                }
            }
        }
        catch(ex: Exception) {
            callbacks.printError(ex.toString())
        }
    }

    override fun processHttpMessage(toolFlag: Int, isRequest: Boolean, messageInfo: IHttpRequestResponse) {
        try {
            if (isRequest) {
                val rc = processOutbound(parseRequest(messageInfo.request))
                if(rc != null) {
                    messageInfo.request = rc
                }
            } else {
                val rc = processInbound(parseResponse(messageInfo.response))
                if (rc != null) {
                    messageInfo.response = rc
                }
            }
        }
        catch(ex: Exception) {
            callbacks.printError(ex.toString())
        }
    }

    fun parseRequest(request: ByteArray): MessageInfo {
        val requestInfo = callbacks.helpers.analyzeRequest(request)
        var body = request.copyOfRange(requestInfo.bodyOffset, request.size)
        return MessageInfo(requestInfo.headers, body)
    }

    fun parseResponse(response: ByteArray): MessageInfo {
        val responseInfo = callbacks.helpers.analyzeResponse(response)
        var body = response.copyOfRange(responseInfo.bodyOffset, response.size)
        return MessageInfo(responseInfo.headers, body)
    }

    fun processInbound(message: MessageInfo):ByteArray? {
        val contentTypeHeader = findHeader(message.headers, CONTENT_TYPE)
        if(contentTypeHeader == null) {
            return null
        }
        val match = CHARSET.find(contentTypeHeader)
        if(match == null) {
            return null
        }

        val charset = match.groupValues.get(1)
        val body = String(message.body, Charsets.UTF_8).toByteArray(Charset.forName(charset))
        val headers = message.headers
        headers.remove(contentTypeHeader)
        headers.add(contentTypeHeader.replace(charset, "utf-8"))
        headers.add(ORIGINAL_CHARSET + charset)
        return callbacks.helpers.buildHttpMessage(headers, body)
    }

    fun processOutbound(message: MessageInfo):ByteArray? {
        val originalCharsetHeader = findHeader(message.headers, ORIGINAL_CHARSET)
        if(originalCharsetHeader == null) {
            return null
        }
        val charset = originalCharsetHeader.substringAfter(ORIGINAL_CHARSET)
        val newBody = String(message.body, Charsets.UTF_8).toByteArray(Charset.forName(charset))

        val contentTypeHeader = findHeader(message.headers, CONTENT_TYPE)!!
        val headers = message.headers
        headers.remove(originalCharsetHeader)
        headers.remove(contentTypeHeader)
        headers.add(contentTypeHeader.replace("utf-8", charset))
        return callbacks.helpers.buildHttpMessage(headers, newBody)
    }

    fun findHeader(headers: List<String>, header: String): String? {
        for (theHeader in headers) {
            if (theHeader.startsWith(header)) {
                return theHeader
            }
        }
        return null
    }
}