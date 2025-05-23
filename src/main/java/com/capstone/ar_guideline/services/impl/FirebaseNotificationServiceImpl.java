package com.capstone.ar_guideline.services.impl;

import com.capstone.ar_guideline.dtos.requests.Devices.DeviceRegistrationRequest;
import com.capstone.ar_guideline.exceptions.AppException;
import com.capstone.ar_guideline.exceptions.ErrorCode;
import com.capstone.ar_guideline.services.IFirebaseNotificationService;
import com.google.firebase.messaging.*;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
@Slf4j
public class FirebaseNotificationServiceImpl implements IFirebaseNotificationService {

  @Override
  public Boolean registerDeviceToken(DeviceRegistrationRequest request) {
    try {
      // Here you would typically store the token in your database
      // associated with the user and company

      // Auto-subscribe to company topic
      String companyTopic = "company_" + request.getCompanyId();
      subscribeToTopic(request.getToken(), companyTopic);

      log.info(
          "Device token registered: {} for user: {} in company: {}",
          request.getToken(),
          request.getUserId(),
          request.getCompanyId());
      return true;
    } catch (Exception e) {
      log.error("Failed to register device token", e);
      throw new AppException(ErrorCode.NOTIFICATION_REGISTRATION_FAILED);
    }
  }

  @Override
  public Boolean subscribeToTopic(String token, String topic) {
    try {
      // Subscribe the token to the topic
      TopicManagementResponse response =
          FirebaseMessaging.getInstance().subscribeToTopic(Arrays.asList(token), topic);

      log.info(
          "Successfully subscribed to topic: {}, successes: {}, failures: {}",
          topic,
          response.getSuccessCount(),
          response.getFailureCount());

      return response.getSuccessCount() > 0;
    } catch (FirebaseMessagingException e) {
      log.error("Failed to subscribe to topic: " + topic, e);
      throw new AppException(ErrorCode.TOPIC_SUBSCRIPTION_FAILED);
    }
  }

  @Override
  public Boolean unsubscribeFromTopic(String token, String topic) {
    try {
      // Unsubscribe the token from the topic
      TopicManagementResponse response =
          FirebaseMessaging.getInstance().unsubscribeFromTopic(Arrays.asList(token), topic);

      log.info(
          "Successfully unsubscribed from topic: {}, successes: {}, failures: {}",
          topic,
          response.getSuccessCount(),
          response.getFailureCount());

      return response.getSuccessCount() > 0;
    } catch (FirebaseMessagingException e) {
      log.error("Failed to unsubscribe from topic: " + topic, e);
      throw new AppException(ErrorCode.TOPIC_UNSUBSCRIPTION_FAILED);
    }
  }

  @Override
  public String sendNotificationToTopic(String topic, String title, String body, String data) {
    try {
      // Create notification message
      Message.Builder messageBuilder =
          Message.builder()
              .setNotification(Notification.builder().setTitle(title).setBody(body).build())
              .setTopic(topic);

      // Add data payload if provided
      if (data != null && !data.isEmpty()) {
        Map<String, String> dataMap = parseDataString(data);
        messageBuilder.putAllData(dataMap);
      }

      // Send the message
      String response = FirebaseMessaging.getInstance().send(messageBuilder.build());
      log.info("Successfully sent message to topic: {}, response: {}", topic, response);

      return response;
    } catch (FirebaseMessagingException e) {
      log.error("Failed to send message to topic: " + topic, e);
      throw new AppException(ErrorCode.NOTIFICATION_SEND_FAILED);
    }
  }

  @Override
  public String sendNotificationToToken(String token, String title, String body, String data) {
    try {
      // Create notification message
      Message.Builder messageBuilder =
          Message.builder()
              .setNotification(Notification.builder().setTitle(title).setBody(body).build())
              .setToken(token);

      // Add data payload if provided
      if (data != null && !data.isEmpty()) {
        Map<String, String> dataMap = parseDataString(data);
        messageBuilder.putAllData(dataMap);
      }

      // Send the message
      String response = FirebaseMessaging.getInstance().send(messageBuilder.build());
      log.info("Successfully sent message to token: {}, response: {}", token, response);

      return response;
    } catch (FirebaseMessagingException e) {
      log.error("Failed to send message to token: " + token, e);
      throw new AppException(ErrorCode.NOTIFICATION_SEND_FAILED);
    }
  }

  // Helper method to parse data string in format "key1:value1,key2:value2"
  private Map<String, String> parseDataString(String data) {
    Map<String, String> dataMap = new HashMap<>();

    if (data != null && !data.isEmpty()) {
      String[] pairs = data.split(",");
      for (String pair : pairs) {
        String[] keyValue = pair.split(":");
        if (keyValue.length == 2) {
          dataMap.put(keyValue[0].trim(), keyValue[1].trim());
        }
      }
    }

    return dataMap;
  }
}
