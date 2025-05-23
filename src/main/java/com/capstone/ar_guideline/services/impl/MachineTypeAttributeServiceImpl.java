package com.capstone.ar_guideline.services.impl;

import com.capstone.ar_guideline.dtos.responses.MachineTypeAttribute.MachineTypeAttributeResponse;
import com.capstone.ar_guideline.entities.MachineTypeAttribute;
import com.capstone.ar_guideline.exceptions.AppException;
import com.capstone.ar_guideline.exceptions.ErrorCode;
import com.capstone.ar_guideline.mappers.MachineTypeAttributeMapper;
import com.capstone.ar_guideline.repositories.MachineTypeAttributeRepository;
import com.capstone.ar_guideline.services.IMachineTypeAttributeService;
import java.util.List;
import java.util.Optional;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
@Slf4j
public class MachineTypeAttributeServiceImpl implements IMachineTypeAttributeService {
  MachineTypeAttributeRepository machineTypeAttributeRepository;

  @Override
  public MachineTypeAttribute create(MachineTypeAttribute machineTypeAttribute) {
    try {
      return machineTypeAttributeRepository.save(machineTypeAttribute);
    } catch (Exception exception) {
      if (exception instanceof AppException) {
        throw exception;
      }
      throw new AppException(ErrorCode.MACHINE_TYPE_ATTRIBUTE_CREATE_FAILED);
    }
  }

  @Override
  public MachineTypeAttribute update(String id, MachineTypeAttribute machineTypeAttribute) {
    try {
      findById(id);
      return machineTypeAttributeRepository.save(machineTypeAttribute);
    } catch (Exception exception) {
      if (exception instanceof AppException) {
        throw exception;
      }
      throw new AppException(ErrorCode.MACHINE_TYPE_ATTRIBUTE_UPDATE_FAILED);
    }
  }

  @Override
  public void delete(String id) {
    try {
      MachineTypeAttribute machineTypeAttributeById = findById(id);

      machineTypeAttributeRepository.deleteById(machineTypeAttributeById.getId());
    } catch (Exception exception) {
      if (exception instanceof AppException) {
        throw exception;
      }
      throw new AppException(ErrorCode.MACHINE_TYPE_ATTRIBUTE_DELETE_FAILED);
    }
  }

  @Override
  public MachineTypeAttribute findById(String id) {
    try {
      return machineTypeAttributeRepository
          .findById(id)
          .orElseThrow(() -> new AppException(ErrorCode.MODEL_TYPE_NOT_EXISTED));
    } catch (Exception exception) {
      if (exception instanceof AppException) {
        throw exception;
      }
      throw new AppException(ErrorCode.MACHINE_TYPE_ATTRIBUTE_NOT_EXISTED);
    }
  }

  @Override
  public MachineTypeAttribute findByIdNotThrowException(String id) {
    try {
      Optional<MachineTypeAttribute> machineTypeAttributeById =
          machineTypeAttributeRepository.findById(id);

      return machineTypeAttributeById.orElse(null);

    } catch (Exception exception) {
      if (exception instanceof AppException) {
        throw exception;
      }
      throw new AppException(ErrorCode.MACHINE_TYPE_ATTRIBUTE_NOT_EXISTED);
    }
  }

  @Override
  public List<MachineTypeAttributeResponse> getMachineTypeAttributeByMachineTypeId(
      String machineTypeId) {
    try {
      List<MachineTypeAttribute> machineTypeAttributes =
          machineTypeAttributeRepository.getMachineTypeAttributeByMachineTypeId(machineTypeId);

      return machineTypeAttributes.stream()
          .map(MachineTypeAttributeMapper::fromEntityToMachineTypeAttributeResponse)
          .toList();
    } catch (Exception exception) {
      if (exception instanceof AppException) {
        throw exception;
      }
      throw new AppException(ErrorCode.MACHINE_TYPE_ATTRIBUTE_NOT_EXISTED);
    }
  }

  @Override
  public List<MachineTypeAttribute> getByMachineTypeId(String machineTypeId) {
    try {
      return machineTypeAttributeRepository.getMachineTypeAttributeByMachineTypeId(machineTypeId);
    } catch (Exception exception) {
      if (exception instanceof AppException) {
        throw exception;
      }
      throw new AppException(ErrorCode.MACHINE_TYPE_ATTRIBUTE_NOT_EXISTED);
    }
  }

  @Override
  public Integer countNumOfAttributeByMachineTypeId(String machineTypeId) {
    try {
      return machineTypeAttributeRepository.countNumOfAttributeById(machineTypeId);
    } catch (Exception exception) {
      if (exception instanceof AppException) {
        throw exception;
      }
      throw new AppException(ErrorCode.MACHINE_TYPE_ATTRIBUTE_NOT_EXISTED);
    }
  }
}
