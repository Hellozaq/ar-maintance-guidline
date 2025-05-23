package com.capstone.ar_guideline.services.impl;

import com.capstone.ar_guideline.constants.ConstStatus;
import com.capstone.ar_guideline.entities.PointOptions;
import com.capstone.ar_guideline.repositories.PointOptionsRepository;
import java.util.List;
import java.util.Optional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class PointOptionsService {

  @Autowired private PointOptionsRepository pointOptionsRepository;

  public PointOptions create(PointOptions pointOptions) {
    return pointOptionsRepository.save(pointOptions);
  }

  public PointOptions update(String id, PointOptions pointOptionsDetails) {
    Optional<PointOptions> optionalPointOptions = pointOptionsRepository.findById(id);
    if (optionalPointOptions.isPresent()) {
      PointOptions pointOptions = optionalPointOptions.get();
      pointOptions.setName(pointOptionsDetails.getName());
      pointOptions.setAmount(pointOptionsDetails.getAmount());
      pointOptions.setPoint(pointOptionsDetails.getPoint());
      pointOptions.setCurrency(pointOptionsDetails.getCurrency());
      return pointOptionsRepository.save(pointOptions);
    } else {
      throw new RuntimeException("PointOptions not found");
    }
  }

  public List<PointOptions> getAllForCompany() {
    return pointOptionsRepository.findAllByStatusOrderByPointAsc(ConstStatus.ACTIVE_STATUS);
  }

  public List<PointOptions> getAllForAdmin() {
    return pointOptionsRepository.findAllByOrderByPointAsc();
  }

  public void delete(String id) {
    Optional<PointOptions> optionalPointOptions = pointOptionsRepository.findById(id);
    if (optionalPointOptions.isPresent()) {
      PointOptions pointOptions = optionalPointOptions.get();
      if (pointOptions.getOrderTransactions().isEmpty()) {
        pointOptionsRepository.deleteById(id);
      } else {
        throw new RuntimeException("Cannot delete PointOptions with associated OrderTransactions");
      }
    } else {
      throw new RuntimeException("PointOptions not found");
    }
  }

  public PointOptions findById(String id) {
    return pointOptionsRepository.findById(id).get();
  }

  public void changeStatus(String id) {
    PointOptions pointOptions = pointOptionsRepository.findById(id).get();
    String status = ConstStatus.ACTIVE_STATUS;
    if (pointOptions.getStatus().equals(ConstStatus.ACTIVE_STATUS)) {
      status = ConstStatus.INACTIVE_STATUS;
    }
    pointOptions.setStatus(status);
    pointOptionsRepository.save(pointOptions);
  }
}
