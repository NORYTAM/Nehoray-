/**
 * Human-readable labels for every privacy key / DB column that can appear in
 * info_requests.field_name. Keys cover BOTH the camelCase privacy key names
 * (as stored in info_requests.field_name) and their snake_case DB column
 * equivalents, so look-ups work regardless of which form is used.
 */
export const FIELD_LABELS: { [key: string]: string } = {
  // camelCase privacy keys (stored in info_requests.field_name)
  torahLearning: 'Torah learning',
  educationLevel: 'Education level',
  hasChildren: 'Children status',
  // snake_case DB column name aliases
  torah_learning: 'Torah learning',
  education_level: 'Education level',
  has_children: 'Children status',
  // Fields whose privacy key and DB column are identical
  pictures: 'Photos',
  height: 'Height',
  dob: 'Date of birth',
  phone: 'Phone number',
  email: 'Email address',
  whatsapp: 'WhatsApp number',
  location_city: 'City',
  location_state: 'State',
  location_country: 'Country',
  languages: 'Languages',
  nationality: 'Background/nationality',
  is_cohen: 'Cohen status',
  hashkafa_type: 'Hashkafa',
  praying: 'Prayer habits',
  post_high_school_path: 'Post-high school path',
  current_occupation_study: 'Occupation/study',
  plan_after_marriage: 'Plan after marriage',
  what_looking_for: "What they're looking for",
  marital_status: 'Marital status',
  dress_style: 'Dress style',
  wears_black_hat: 'Black hat',
  head_covering: 'Head covering',
  smoking: 'Smoking habits',
  alcohol_consumption: 'Alcohol consumption',
};

/**
 * Maps camelCase privacy keys (stored in info_requests.field_name) to the
 * actual snake_case column names on the profiles table. Only entries that
 * differ need to be listed here.
 */
export const PRIVACY_KEY_TO_DB_COLUMN: { [key: string]: string } = {
  torahLearning: 'torah_learning',
  educationLevel: 'education_level',
  hasChildren: 'has_children',
};

/** Reverse mapping used when a database field is checked against form Ask Me keys. */
export const DB_COLUMN_TO_PRIVACY_KEY: { [key: string]: string } = {
  torah_learning: 'torahLearning',
  education_level: 'educationLevel',
  has_children: 'hasChildren',
  location_city: 'location',
  location_state: 'location',
  location_country: 'location',
  is_cohen: 'isCohen',
  hashkafa_type: 'hashkafaType',
  post_high_school_path: 'postHighSchoolPath',
  current_occupation_study: 'currentOccupationStudy',
  plan_after_marriage: 'planAfterMarriage',
  marital_status: 'maritalStatus',
  dress_style: 'dressStyle',
  wears_black_hat: 'wearsBlackHat',
  head_covering: 'headCovering',
  alcohol_consumption: 'alcoholConsumption',
};

/**
 * Returns the human-readable label for a field name.
 * Handles direct matches, camelCase, snake_case, and all-lowercase variants
 * that may be stored in info_requests.field_name.
 */
export const getFieldLabel = (fieldName: string): string => {
  if (!fieldName) return fieldName;
  // 1. Direct match (camelCase or snake_case as stored in FIELD_LABELS)
  if (FIELD_LABELS[fieldName]) return FIELD_LABELS[fieldName];
  // 2. Case-insensitive fallback (handles "educationlevel", "torahlearning", etc.)
  const lower = fieldName.toLowerCase();
  const key = Object.keys(FIELD_LABELS).find((k) => k.toLowerCase() === lower);
  return key ? FIELD_LABELS[key] : fieldName;
};
