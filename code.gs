// Bulild the new Card
function buildMainCard(e) {
  var messageId = e.gmail.messageId;
  var action = CardService.newAction()
      .setFunctionName('analyzeEmailAction')
      .setParameters({'messageId': messageId});
  var button = CardService.newTextButton()
      .setText('Scan for Threats')
      .setOnClickAction(action);
  var section = CardService.newCardSection()
      .addWidget(CardService.newTextParagraph().setText("Ready to scan this email with Malicious Email Scorer?"))
      .addWidget(button);
  var card = CardService.newCardBuilder()
      .setHeader(CardService.newCardHeader().setTitle("Malicious Email Scorer"))
      .addSection(section)
      .build();
  return [card];
}

// Analyzer
function analyzeEmailAction(e) {
  // Update according to the terminal info - using ngrok to connect between google and the local computer
  var backendUrl = "https://XXXX.dev/analyze"; 

  var messageId = (e.parameters && e.parameters.messageId) || (e.gmail && e.gmail.messageId);
  
  if (!messageId) {
    return CardService.newActionResponseBuilder()
        .setNotification(CardService.newNotification().setText("Error: Message ID not found"))
        .build();
  }

try {
  var message = GmailApp.getMessageById(messageId);
  // Check attacments
  var attachments = message.getAttachments();
  var attachmentData = attachments.map(function(att) {
    return {
      "name": att.getName(),
      "contentType": att.getContentType()
    };
  });
    
  var payload = {
    "subject": message.getSubject() || "",
    "sender": message.getFrom() || "",
    "body": message.getPlainBody() || "",
    "rawContent": message.getRawContent() || "", // Headers - SPF
    "user_email": Session.getEffectiveUser().getEmail(), // who sent the email
    "attachments": attachmentData // The files
  };

    var options = {
      "method": "post",
      "contentType": "application/json",
      "headers": {
        "ngrok-skip-browser-warning": "true" // Free ngrok - Warning page
      },
      "payload": JSON.stringify(payload), // Convert to string
      "muteHttpExceptions": true // When HTTP error continue and get server responed
    };

    var response = UrlFetchApp.fetch(backendUrl, options); // Waiting for the server respond
    var responseData = JSON.parse(response.getContentText()); // Convert from string to object

    var header = CardService.newCardHeader()
        .setTitle("Analysis Result")
        .setSubtitle("Confidence: " + responseData.score_percent);

    var section = CardService.newCardSection()
        .addWidget(CardService.newTextParagraph()
            .setText("Security Status: <b><font color=\"" + responseData.risk_color + "\">" + responseData.risk_level + "</font></b>"))
        .addWidget(CardService.newTextParagraph()
            .setText("<b>Details:</b><br>" + responseData.reasoning));

    var card = CardService.newCardBuilder()
        .setHeader(header)
        .addSection(section)
        .build();

    // Response according the user actions
    return CardService.newActionResponseBuilder()
        .setNavigation(CardService.newNavigation().pushCard(card)) // The new card with the info
        .build();

  } catch (err) { // Fail
    return CardService.newActionResponseBuilder()
        .setNotification(CardService.newNotification().setText("Google Says: " + err.message))
        .build();
  }
}

/**
 * OAuth Authorization Helper
 * Run this function manually from the editor to grant necessary permissions.
 * Essential after modifying scopes in appsscript.json or during initial setup.
 */
function authorizeMe() {
  var email = Session.getEffectiveUser().getEmail();
  Logger.log("Authorized successfully for: " + email);
}

function forceAuth() {
  UrlFetchApp.fetch("https://google.com"); // Command that sends an HTTP request (browse) to an external website
}