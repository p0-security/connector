type SelectOption = {
  key: string;
  value: string;
};

type SelectOptionGroup = {
  /**
   * The resource key used when making a request for this resource.
   */
  key: string;
  /**
   * A human-readable name for the resource.
   */
  value: string;
  /**
   * The group that this resource option belongs to.
   */
  group: string;
};

export type SelectItem = SelectOption | SelectOptionGroup;
