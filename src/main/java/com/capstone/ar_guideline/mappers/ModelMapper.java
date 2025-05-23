package com.capstone.ar_guideline.mappers;

import com.capstone.ar_guideline.dtos.requests.Model.ModelCreationRequest;
import com.capstone.ar_guideline.dtos.responses.Model.ModelResponse;
import com.capstone.ar_guideline.entities.Company;
import com.capstone.ar_guideline.entities.Model;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

public class ModelMapper {

  // In ModelMapper class
  public static Model fromModelCreationRequestToEntity(ModelCreationRequest request) {
    return Model.builder()
        .status(request.getStatus())
        .modelCode(request.getModelCode())
        .name(request.getName() != null ? request.getName() : null)
        .company(Company.builder().id(request.getCompanyId()).build())
        .description(request.getDescription() != null ? request.getDescription() : null)
        .version(request.getVersion())
        .scale(request.getScale())
        .position(
            request.getPosition() != null
                ? request.getPosition().stream()
                    .map(String::valueOf)
                    .collect(Collectors.joining(", "))
                : null)
        .rotation(
            request.getRotation() != null
                ? request.getRotation().stream()
                    .map(String::valueOf)
                    .collect(Collectors.joining(", "))
                : null)
        .build();
  }

  public static Model fromModelCreationRequestToEntityForUpdate(ModelCreationRequest request) {
    return Model.builder()
        .status(request.getStatus())
        .modelCode(request.getModelCode())
        .name(request.getName())
        .description(request.getDescription())
        .version(request.getVersion())
        .scale(request.getScale())
        .build();
  }

  public static ModelResponse fromEntityToModelResponse(Model model) {
    return ModelResponse.builder()
        .id(model.getId())
        .modelCode(model.getModelCode())
        .status(model.getStatus())
        .isUsed(model.getIsUsed())
        .name(model.getName())
        .modelTypeId(model.getModelType() != null ? model.getModelType().getId() : null)
        .modelTypeName(model.getModelType() != null ? model.getModelType().getName() : null)
        .description(model.getDescription())
        .companyId(model.getCompany().getId())
        .imageUrl(model.getImageUrl())
        .version(model.getVersion())
        .scale(model.getScale())
        .file(model.getFile())
        .position(parseStringToFloatList(model.getPosition()))
        .rotation(parseStringToFloatList(model.getRotation()))
        .build();
  }

  // Helper method to convert a comma-separated string to a List<Float>
  private static List<Float> parseStringToFloatList(String input) {
    if (input == null || input.isEmpty()) {
      return Collections.emptyList();
    }
    return Arrays.stream(input.split(","))
        .map(String::trim)
        .map(Float::parseFloat)
        .collect(Collectors.toList());
  }
}
