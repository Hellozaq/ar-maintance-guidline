package com.capstone.ar_guideline.services;

import com.capstone.ar_guideline.dtos.requests.InstructionDetail.InstructionDetailCreationRequest;
import com.capstone.ar_guideline.dtos.responses.InstructionDetail.InstructionDetailResponse;
import com.capstone.ar_guideline.entities.InstructionDetail;
import java.util.List;

public interface IInstructionDetailService {
  InstructionDetailResponse create(InstructionDetailCreationRequest request);

  InstructionDetailResponse update(String id, InstructionDetailCreationRequest request);

  void delete(String id);

  InstructionDetail findById(String id);

  InstructionDetailResponse findByIdReturnResponse(String id);

  List<InstructionDetail> findByInstructionId(String instructionId);

  List<InstructionDetailResponse> findByInstructionIdReturnResponse(String instructionId);

  Boolean swapOrder(String instructionDetailIdCurrent, String instructionDetailIdSwap);

  Boolean deleteByInstructionId(String instructionId);

  Long countInstructionDetailByCourseId(String courseId);
}
