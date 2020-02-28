from burp import IBurpExtender, IParameter, IRequestInfo, ISessionHandlingAction, ITab
from java.net import URL
from HTMLParser import HTMLParser
from java.awt import GridBagConstraints, GridBagLayout
from javax.swing import JCheckBox, JLabel, JPanel, JTextField
from logging import Formatter, StreamHandler, getLogger, ERROR, INFO, DEBUG
from sys import stdout

EXTENSION_NAME = 'Anti-CSRF token from referer'
EXTENSION_VERSION = '0.1'
EXTENSION_NAME_VERSION = EXTENSION_NAME + ' ' + EXTENSION_VERSION

# Configure the logger
LOG_LEVEL = ERROR
FMT = '%(asctime)s:%(msecs)03d [%(levelname)s] %(message)s'
DATEFMT = '%H:%M:%S'

# Configure the constants
CSRF_NAME_PLACEHOLDER = '#csrf_name#'
HEADER_NAME_VALUE_SEPARATOR = ': '
REFERER_HEADER_NAME = 'Referer'
HEADER_NAMES_TO_EXCLUDE = ['Host', 'Content-Length', 'Content-Type']
NEWLINE = '\r\n'

class BurpExtender(IBurpExtender, ISessionHandlingAction, ITab):
    def registerExtenderCallbacks(self, callbacks):
        """IBurpExtender"""
        callbacks.setExtensionName(EXTENSION_NAME)
        
        self._helpers = callbacks.getHelpers()
        self._callbacks = callbacks
        self._html_parser = HTMLParser()
        
        self._logger = getLogger(__name__)
        self.initialize_logger()
        
        self.build_gui()
        
        callbacks.registerSessionHandlingAction(self)
        callbacks.addSuiteTab(self)
        
        self._logger.info(EXTENSION_NAME_VERSION)
    
    def getActionName(self):
        """ISessionHandlingAction"""
        return EXTENSION_NAME
    
    def performAction(self, current_request, macro_items):
        """ISessionHandlingAction"""
        # Read the configured values
        csrf_name_contains = self._csrf_name_contains_field.text
        csrf_start_marker = self._csrf_start_marker_field.text
        csrf_end_marker = self._csrf_end_marker_field.text
        do_html_decode = self._do_html_decode.isSelected()
        do_url_decode = self._do_url_decode.isSelected()
        do_url_encode = self._do_url_encode.isSelected()
        
        self._logger.debug('Name of the anti-CSRF token (or part of): %s', csrf_name_contains)
        self._logger.debug('Start marker of the anti-CSRF token in the response: %s', csrf_start_marker)
        self._logger.debug('End marker of the anti-CSRF token in the response: %s', csrf_end_marker)
        self._logger.debug('HTML decode the anti-CSRF token: %s', do_html_decode)
        self._logger.debug('URL decode the anti-CSRF token: %s', do_url_decode)
        self._logger.debug('URL encode the anti-CSRF token: %s', do_url_encode)
        
        request_info = self._helpers.analyzeRequest(current_request)
        self._logger.info('Handling request to: %s %s', request_info.getMethod(), request_info.getUrl().toString())
        
        # Iterate over the parameters to find the first anti-CSRF one
        csrf_name = None
        csrf_type = None
        for parameter in request_info.getParameters():
            parameter_name = parameter.getName()
            parameter_type = parameter.getType()
            self._logger.debug('Parameter found: (%s, %d)', parameter_name, parameter_type)
            
            if csrf_name_contains in parameter_name:
                csrf_name = parameter_name
                csrf_type = parameter_type
                self._logger.info('Anti-CSRF parameter found: %s', parameter_name)
                break
        
        if csrf_name is None or csrf_type is None:
            self._logger.info('No anti-CSRF token parameter in request')
            return
        
        # Iterate over the headers to find the referer and to extract the headers to copy
        get_csrf_request_headers = ""
        referer_url = None
        for header in request_info.getHeaders():
            self._logger.debug('Header found: %s', header)
            
            header_split = header.split(HEADER_NAME_VALUE_SEPARATOR, 1)
            if len(header_split) < 2:
                continue
            
            header_name = header_split[0]
            header_value = header_split[1]
            
            # We first look for the referer, so it will never be copied in the request to the referer and thus avoids loops
            if header_name == REFERER_HEADER_NAME:
                referer_url = header_value
                self._logger.debug('Referer URL found')
            elif header_name not in HEADER_NAMES_TO_EXCLUDE:
                get_csrf_request_headers += header + NEWLINE
        
        if referer_url is None:
            self._logger.info('No referer URL found')
            return
        
        # Build a GET request to the referer URL
        get_csrf_request = self._helpers.buildHttpRequest(URL(referer_url))
        get_csrf_request = self.delete_headers(get_csrf_request)
        get_csrf_request += self._helpers.stringToBytes(get_csrf_request_headers + NEWLINE)
        
        # Make the request
        self._logger.info('Request for anti-CSRF request to: %s', referer_url)
        get_csrf_response = self._callbacks.makeHttpRequest(current_request.getHttpService(), get_csrf_request).getResponse()
        
        # Replace the anti-CSRF token name in the anti-CSRF start and end markers
        csrf_start_marker = csrf_start_marker.replace(CSRF_NAME_PLACEHOLDER, csrf_name)
        csrf_end_marker = csrf_end_marker.replace(CSRF_NAME_PLACEHOLDER, csrf_name)
        self._logger.debug('Extract data from string %s to string %s', csrf_start_marker, csrf_end_marker)
        
        # Extract anti-CSRF value from the response
        csrf_value = self.extract_by_markers(get_csrf_response, csrf_start_marker, csrf_end_marker)
        if csrf_value == None:
            self._logger.error('No anti-CSRF token parameter found in response')
            return
        
        self._logger.debug('Anti-CSRF token parameter value before decoding and encoding: %s', csrf_value)
        
        if do_html_decode:
            self._logger.debug('Perform HTML decode')
            csrf_value = self._html_parser.unescape(csrf_value)
        
        if do_url_decode:
            self._logger.debug('Perform URL decode')
            csrf_value = self._helpers.urlDecode(csrf_value)
        
        if do_url_encode:
            self._logger.debug('Perform URL encode')
            csrf_value = self._helpers.urlEncode(csrf_value)
        
        self._logger.debug('Anti-CSRF token parameter value after decoding and encoding: %s', csrf_value)
        
        # Build a new parameter with the updated value of the anti-CSRF token
        csrf_parameter = self._helpers.buildParameter(csrf_name, csrf_value, csrf_type)
        
        # Let the original request go throuth
        current_request.setRequest(self._helpers.updateParameter(current_request.getRequest(), csrf_parameter))
        self._logger.info('Anti-CSRF token value replaced')
    
    def getTabCaption(self):
        """ITab"""
        return EXTENSION_NAME
    
    def getUiComponent(self):
        """ITab"""
        return self._ui_component
    
    def initialize_logger(self):
        formatter = Formatter(fmt=FMT, datefmt=DATEFMT)
        
        handler = StreamHandler(stream=stdout)
        handler.setFormatter(formatter)
        
        self._logger.addHandler(handler)
        self._logger.setLevel(LOG_LEVEL)
    
    def build_gui(self):
        component = JPanel(GridBagLayout())
        c = GridBagConstraints()
        c.fill = GridBagConstraints.HORIZONTAL
        
        c.gridwidth = 2
        
        # 1st line
        c.gridy = 0
        
        c.gridx = 0
        component.add(JLabel('Don\'t forget to create a Session handling rule invoking this Burp extension under Project options > Sessions and to configure the tool and URL scopes.'), c)
        
        c.gridwidth = 1
        
        # 2nd line
        c.gridy = 1
        
        c.gridx = 0
        component.add(JLabel(' '), c)
        
        # 3rd line
        c.gridy = 2
        
        c.gridx = 0
        component.add(JLabel('Name of the anti-CSRF token, can also be a substring of the name of the anti-CSRF token:'), c)
        
        self._csrf_name_contains_field = JTextField('csrf', 40)
        c.gridx = 1
        component.add(self._csrf_name_contains_field, c)
        
        # 4th line
        c.gridy = 3
        
        c.gridx = 0
        component.add(JLabel('Start marker of the anti-CSRF token in the response, #csrf_name# is replaced by the name of the anti-CSRF token:'), c)
        
        self._csrf_start_marker_field = JTextField('name="' + CSRF_NAME_PLACEHOLDER + '" value="', 40)
        c.gridx = 1
        component.add(self._csrf_start_marker_field, c)
        
        # 5th line
        c.gridy = 4
        
        c.gridx = 0
        component.add(JLabel('End marker of the anti-CSRF token in the response, #csrf_name# is replaced by the name of the anti-CSRF token:'), c)
        
        self._csrf_end_marker_field = JTextField('"', 40)
        c.gridx = 1
        component.add(self._csrf_end_marker_field, c)
        
        # 6th line
        c.gridy = 5
        
        c.gridx = 0
        component.add(JLabel(' '), c)
        
        # 7th line
        c.gridy = 6
        
        c.gridx = 0
        component.add(JLabel('HTML decode the anti-CSRF token:'), c)
        
        self._do_html_decode = JCheckBox("", True)
        c.gridx = 1
        component.add(self._do_html_decode, c)
        
        # 8th line
        c.gridy = 7
        
        c.gridx = 0
        component.add(JLabel('URL decode the anti-CSRF token:'), c)
        
        self._do_url_decode = JCheckBox("", True)
        c.gridx = 1
        component.add(self._do_url_decode, c)
        
        # 9th line
        c.gridy = 8
        
        c.gridx = 0
        component.add(JLabel('URL encode the anti-CSRF token:'), c)
        
        self._do_url_encode = JCheckBox("", True)
        c.gridx = 1
        component.add(self._do_url_encode, c)
        
        # 10th line
        c.gridy = 9
        
        c.gridx = 0
        component.add(JLabel(' '), c)
        
        self._callbacks.customizeUiComponent(component)
        self._ui_component = component
    
    def delete_headers(self, request):
        """Delete all the headers except the first line (e.g. GET...) and the host header"""
        newline_bytes = self._helpers.stringToBytes(NEWLINE)
        first_line_index = self._helpers.indexOf(request, newline_bytes, False, 0, len(request))
        first_line_index += len(newline_bytes)
        second_line_index = self._helpers.indexOf(request, newline_bytes, False, first_line_index, len(request))
        second_line_index += len(newline_bytes)
        return request[:second_line_index]
    
    def extract_by_markers(self, data, start_marker, end_marker):
        """Extract the content between start_marker and end_marker in data"""
        start_marker_bytes= self._helpers.stringToBytes(start_marker)
        end_marker_bytes = self._helpers.stringToBytes(end_marker)
        
        start_index = self._helpers.indexOf(data, start_marker_bytes, False, 0, len(data))
        if start_index == -1:
            self._logger.debug('Start marker not found')
            return None
        
        start_index += len(start_marker_bytes)
        
        end_index = self._helpers.indexOf(data, end_marker_bytes, False, start_index, len(data))
        if end_index == -1:
            self._logger.debug('End marker not found')
            return None
        
        self._logger.debug('Extract data from index %d to index %d', start_index, end_index)
        return self._helpers.bytesToString(data[start_index:end_index])
